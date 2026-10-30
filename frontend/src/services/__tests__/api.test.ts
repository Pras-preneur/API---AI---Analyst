import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  API_BASE_URL,
  ApiError,
  checkHealth,
  checkBackendHealth,
  uploadSpec,
  getProposals,
  getProposal,
  approveProposal,
  rejectProposal,
  executeTests,
  getFindings,
  reviewFinding,
  createReport,
  getReport,
  downloadReportPdf,
  downloadReportJson,
} from '../api';

describe('Frontend API Service Layer', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('Configuration', () => {
    it('defaults to http://127.0.0.1:8000 when VITE_API_URL is unset', () => {
      expect(API_BASE_URL).toMatch(/^http:\/\/127\.0\.0\.1:8000/);
    });
  });

  describe('Health Check', () => {
    it('returns online: true when backend returns status ok', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: 'ok' }),
      } as Response);

      const res = await checkHealth();
      expect(res.online).toBe(true);
      expect(res.status).toBe('ok');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/health'),
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('returns online: true when backend returns status healthy', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: 'healthy' }),
      } as Response);

      const res = await checkHealth();
      expect(res.online).toBe(true);
      expect(res.status).toBe('healthy');
    });

    it('returns online: false when backend is unreachable or throws', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network connection refused'));

      const res = await checkHealth();
      expect(res.online).toBe(false);
      expect(res.status).toBe('offline');
    });

    it('checkBackendHealth formats status for legacy UI consumption', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: 'ok' }),
      } as Response);

      const res = await checkBackendHealth();
      expect(res.online).toBe(true);
      expect(res.message).toBe('Backend Connected');
    });
  });

  describe('OpenAPI Upload & Session Binding', () => {
    it('sends multipart form-data and captures X-Session-ID response header', async () => {
      const mockEndpoints = [
        { path: '/api/users/{id}', method: 'GET', summary: 'Get User' },
        { path: '/api/admin/roles', method: 'POST', summary: 'Set Role' },
      ];
      const mockSessionId = 'sess-uuid-1234-abcd';

      const headers = new Headers();
      headers.set('X-Session-ID', mockSessionId);

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        headers,
        json: async () => mockEndpoints,
      } as unknown as Response);

      const dummyFile = new Blob(['openapi: "3.0.0"\ninfo:\n  title: Test\npaths: {}'], {
        type: 'text/yaml',
      });

      const result = await uploadSpec(dummyFile, 'spec.yaml');

      expect(result.sessionId).toBe(mockSessionId);
      expect(result.endpoints).toHaveLength(2);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/parse-openapi'),
        expect.objectContaining({
          method: 'POST',
          body: expect.any(FormData),
        })
      );
    });

    it('throws ApiError if server returns 400 Bad Request', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ detail: 'Invalid YAML specification' }),
      } as Response);

      const dummyFile = new Blob(['invalid'], { type: 'text/plain' });

      await expect(uploadSpec(dummyFile, 'bad.txt')).rejects.toThrow(
        /Invalid YAML specification/
      );
    });

    it('throws ApiError if server parses spec but omits X-Session-ID', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers(),
        json: async () => [],
      } as unknown as Response);

      const dummyFile = new Blob(['openapi: 3.0.0'], { type: 'text/yaml' });

      await expect(uploadSpec(dummyFile, 'spec.yaml')).rejects.toThrow(
        /required X-Session-ID header/
      );
    });
  });

  describe('Proposal Management', () => {
    const sessionId = 'test-session-5678';

    it('getProposals dispatches POST to /tests/propose with X-Session-ID', async () => {
      const mockProposals = [
        {
          test_id: 'prop-1',
          test_type: 'BOLA',
          severity: 'High',
          status: 'Proposed',
          endpoint: { path: '/items/{id}', method: 'GET' },
        },
      ];

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockProposals,
      } as Response);

      const proposals = await getProposals(sessionId, true);

      expect(proposals).toEqual(mockProposals);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/tests/propose?include_auth=true'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'X-Session-ID': sessionId,
          }),
        })
      );
    });

    it('getProposal retrieves individual test by ID', async () => {
      const mockProposal = {
        test_id: 'prop-99',
        test_type: 'BFLA',
        status: 'Proposed',
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockProposal,
      } as Response);

      const result = await getProposal(sessionId, 'prop-99');
      expect(result).toEqual(mockProposal);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/tests/prop-99'),
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({ 'X-Session-ID': sessionId }),
        })
      );
    });

    it('approveProposal dispatches POST to /tests/{test_id}/approve', async () => {
      const approvedProposal = {
        test_id: 'prop-1',
        status: 'Approved',
        approved_at: '2026-10-31T00:00:00Z',
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => approvedProposal,
      } as Response);

      const result = await approveProposal(sessionId, 'prop-1');

      expect(result.status).toBe('Approved');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/tests/prop-1/approve'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'X-Session-ID': sessionId,
          }),
        })
      );
    });

    it('rejectProposal dispatches POST to /tests/{test_id}/reject', async () => {
      const rejectedProposal = {
        test_id: 'prop-2',
        status: 'Rejected',
        rejected_at: '2026-10-31T00:00:00Z',
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => rejectedProposal,
      } as Response);

      const result = await rejectProposal(sessionId, 'prop-2');

      expect(result.status).toBe('Rejected');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/tests/prop-2/reject'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'X-Session-ID': sessionId,
          }),
        })
      );
    });
  });

  describe('Execution Dispatch', () => {
    const sessionId = 'test-session-exec';

    it('executeTests dispatches POST to /tests/execute with proper payload and header', async () => {
      const mockFindings = [
        {
          finding_id: 'find-1',
          test_id: 'prop-1',
          severity: 'High',
          status: 'Suspected',
          execution_status: 'COMPLETED',
          assessment_outcome: 'SUSPECTED',
          evidence: {
            request: { method: 'GET', url: 'http://127.0.0.1:8001/items/2' },
            response: { status_code: 200, body: '{"item": 2}' },
          },
        },
      ];

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockFindings,
      } as Response);

      const payload = {
        proposal_ids: ['prop-1'],
        target: 'http://127.0.0.1:8001',
      };

      const findings = await executeTests(sessionId, payload);

      expect(findings).toHaveLength(1);
      expect(findings[0].assessment_outcome).toBe('SUSPECTED');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/tests/execute'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-Session-ID': sessionId,
          }),
          body: JSON.stringify(payload),
        })
      );
    });

    it('rejects execution when proposal_ids is empty', async () => {
      await expect(
        executeTests(sessionId, { proposal_ids: [], target: 'http://127.0.0.1:8001' })
      ).rejects.toThrow(/At least one proposal ID must be provided/);
    });

    it('handles backend execution errors gracefully', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ detail: 'Only APPROVED proposals may be executed' }),
      } as Response);

      await expect(
        executeTests(sessionId, {
          proposal_ids: ['unapproved-id'],
          target: 'http://127.0.0.1:8001',
        })
      ).rejects.toThrow(/Only APPROVED proposals may be executed/);
    });
  });

  describe('Findings and Human Review', () => {
    const sessionId = 'test-session-review';

    it('getFindings queries GET /findings with X-Session-ID', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => [{ finding_id: 'f-1' }],
      } as Response);

      const res = await getFindings(sessionId);
      expect(res).toEqual([{ finding_id: 'f-1' }]);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/findings'),
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({ 'X-Session-ID': sessionId }),
        })
      );
    });

    it('reviewFinding submits human confirmation decision', async () => {
      const mockConfirmedFinding = {
        finding_id: 'f-1',
        assessment_outcome: 'CONFIRMED',
        is_human_reviewed: true,
        reviewer_id: 'auditor-1',
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockConfirmedFinding,
      } as Response);

      const res = await reviewFinding(sessionId, 'f-1', {
        outcome: 'CONFIRMED',
        reviewer_id: 'auditor-1',
        reviewer_notes: 'Verified cross-tenant object leakage.',
      });

      expect(res.assessment_outcome).toBe('CONFIRMED');
      expect(res.is_human_reviewed).toBe(true);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/findings/f-1/review'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({ 'X-Session-ID': sessionId }),
        })
      );
    });
  });

  describe('Report Management', () => {
    const sessionId = 'test-session-rep';

    it('createReport dispatches POST /reports with target and X-Session-ID', async () => {
      const mockReport = {
        report_id: 'rep-abc-123',
        session_id: sessionId,
        target_base_url: 'http://127.0.0.1:8001',
        severity_counts: { critical: 1, high: 2, medium: 0, low: 0, unknown: 0 },
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockReport,
      } as Response);

      const report = await createReport(sessionId, 'http://127.0.0.1:8001');

      expect(report.report_id).toBe('rep-abc-123');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/reports'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-Session-ID': sessionId,
          }),
          body: JSON.stringify({ target: 'http://127.0.0.1:8001' }),
        })
      );
    });

    it('getReport retrieves existing report by ID', async () => {
      const mockReport = {
        report_id: 'rep-abc-123',
        session_id: sessionId,
      };

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockReport,
      } as Response);

      const report = await getReport(sessionId, 'rep-abc-123');
      expect(report.report_id).toBe('rep-abc-123');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/reports/rep-abc-123'),
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({ 'X-Session-ID': sessionId }),
        })
      );
    });

    it('downloadReportPdf fetches PDF blob with session header', async () => {
      const mockPdfBlob = new Blob(['%PDF-1.4 mock content'], { type: 'application/pdf' });
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        blob: async () => mockPdfBlob,
      } as Response);

      const blob = await downloadReportPdf(sessionId, 'rep-abc-123');
      expect(blob.type).toBe('application/pdf');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/reports/rep-abc-123/pdf'),
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({ 'X-Session-ID': sessionId }),
        })
      );
    });

    it('downloadReportJson fetches JSON blob with session header', async () => {
      const mockJsonBlob = new Blob(['{"report_id": "rep-abc-123"}'], { type: 'application/json' });
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        blob: async () => mockJsonBlob,
      } as Response);

      const blob = await downloadReportJson(sessionId, 'rep-abc-123');
      expect(blob.type).toBe('application/json');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/reports/rep-abc-123/json'),
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'X-Session-ID': sessionId,
            Accept: 'application/json',
          }),
        })
      );
    });
  });
});
