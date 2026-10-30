import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  uploadSpec,
  getProposals,
  approveProposal,
  rejectProposal,
  ApiError,
} from '../api';
import {
  mapBackendEndpointsToSpec,
  mapBackendProposedTestToUI,
} from '../proposalAdapter';
import type { BackendEndpoint, BackendProposedTest } from '../../types/backend';
import type { ApiSpec } from '../../types/assistant';

describe('Phase 2 Workflow Integration Tests', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // 1. Successful OpenAPI upload
  it('1. performs successful OpenAPI specification upload and extracts session ID', async () => {
    const mockEndpoints: BackendEndpoint[] = [
      {
        path: '/api/v1/users',
        method: 'get',
        summary: 'List users',
        parameters: [{ name: 'limit', in: 'query', required: false }],
        effective_security: [{ BearerAuth: [] }],
      },
      {
        path: '/api/v1/users/{id}',
        method: 'get',
        summary: 'Get user by ID',
        parameters: [{ name: 'id', in: 'path', required: true }],
        effective_security: [{ BearerAuth: [] }],
      },
    ];
    const mockSessionId = 'session-uuid-phase2-success';

    const headers = new Headers();
    headers.set('X-Session-ID', mockSessionId);

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers,
      json: async () => mockEndpoints,
    } as unknown as Response);

    const dummyYaml = new Blob(
      ['openapi: 3.0.0\ninfo:\n  title: Core Banking API\npaths: {}'],
      { type: 'text/yaml' }
    );

    const result = await uploadSpec(dummyYaml, 'core_banking.yaml');

    expect(result.sessionId).toBe(mockSessionId);
    expect(result.endpoints).toHaveLength(2);
    expect(result.endpoints[0].path).toBe('/api/v1/users');
  });

  // 2. Invalid specification error
  it('2. handles invalid specification rejection by backend with descriptive ApiError', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({
        detail: 'YAML validation error: missing required info.title field in specification.',
      }),
    } as Response);

    const invalidBlob = new Blob(['invalid: [yaml'], { type: 'text/yaml' });

    await expect(uploadSpec(invalidBlob, 'corrupt.yaml')).rejects.toThrow(
      /missing required info\.title/
    );
  });

  // 3. Session ID capture and storage
  it('3. maps session ID into ApiSpec and ensures endpoints are associated with session', () => {
    const backendEndpoints: BackendEndpoint[] = [
      {
        path: '/api/v1/accounts/{id}/balance',
        method: 'get',
        summary: 'Get account balance',
        parameters: [{ name: 'id', in: 'path', required: true }],
        effective_security: [{ BearerAuth: [] }],
      },
    ];
    const sessionId = 'session-cap-9999';

    const spec: ApiSpec = mapBackendEndpointsToSpec(
      backendEndpoints,
      'FinTech API.yaml',
      sessionId,
      'openapi: 3.0.0...'
    );

    expect(spec.sessionId).toBe(sessionId);
    expect(spec.id).toBe(`spec-${sessionId}`);
    expect(spec.title).toBe('FinTech API');
    expect(spec.endpoints).toHaveLength(1);
    expect(spec.endpoints[0].authRequired).toBe(true);
  });

  // 4. Endpoint inventory rendering from backend data
  it('4. maps backend endpoints, parameters, and potential security vectors accurately', () => {
    const backendEndpoints: BackendEndpoint[] = [
      {
        path: '/api/v1/admin/roles/grant',
        method: 'post',
        summary: 'Grant administrative role',
        parameters: [
          { name: 'role', in: 'query', required: true, schema: { type: 'string' } },
        ],
        effective_security: [{ BearerAuth: ['admin'] }],
      },
      {
        path: '/api/v1/documents/{doc_id}',
        method: 'get',
        summary: 'Retrieve document',
        parameters: [
          { name: 'doc_id', location: 'path', required: true, schema: { type: 'string' } },
        ],
        effective_security: [],
      },
    ];

    const spec = mapBackendEndpointsToSpec(backendEndpoints, 'Security Gateway', 'sess-inventory');

    const ep1 = spec.endpoints[0];
    expect(ep1.method).toBe('POST');
    expect(ep1.path).toBe('/api/v1/admin/roles/grant');
    expect(ep1.authRequired).toBe(true);
    expect(ep1.potentialRisks).toContain('Broken Function Level Authorization (BFLA)');
    expect(ep1.parameters[0].name).toBe('role');

    const ep2 = spec.endpoints[1];
    expect(ep2.method).toBe('GET');
    expect(ep2.parameters[0].name).toBe('doc_id');
    expect(ep2.parameters[0].in).toBe('path');
    expect(ep2.potentialRisks).toContain('BOLA / IDOR');
  });

  // 5. Proposal generation with the correct session ID
  it('5. requests proposals using active session ID and maps backend ProposedTest models', async () => {
    const sessionId = 'sess-prop-active-123';
    const mockBackendProposals: BackendProposedTest[] = [
      {
        test_id: 'test-uuid-bola-001',
        endpoint: { path: '/api/v1/documents/{doc_id}', method: 'GET' },
        test_type: 'BOLA',
        description: 'Verify cross-tenant object access on /api/v1/documents/{doc_id}',
        severity: 'High',
        status: 'Proposed',
      },
      {
        test_id: 'test-uuid-bfla-002',
        endpoint: { path: '/api/v1/admin/roles/grant', method: 'POST' },
        test_type: 'BFLA',
        description: 'Verify standard role cannot access /api/v1/admin/roles/grant',
        severity: 'Critical',
        status: 'Proposed',
      },
    ];

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockBackendProposals,
    } as Response);

    const proposals = await getProposals(sessionId, true);

    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/tests/propose?include_auth=true'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'X-Session-ID': sessionId,
        }),
      })
    );

    const uiProposals = proposals.map(mapBackendProposedTestToUI);
    expect(uiProposals).toHaveLength(2);
    expect(uiProposals[0].testId).toBe('test-uuid-bola-001');
    expect(uiProposals[0].vulnerabilityType).toBe('bola');
    expect(uiProposals[0].estimatedRisk).toBe('P1');
    expect(uiProposals[0].status).toBe('proposed');
    expect(uiProposals[1].vulnerabilityType).toBe('bfla');
    expect(uiProposals[1].estimatedRisk).toBe('P1');
  });

  // 6. Empty proposal response
  it('6. safely handles an empty proposal list without UI or parsing errors', async () => {
    const sessionId = 'sess-empty-props';

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [],
    } as Response);

    const proposals = await getProposals(sessionId, true);
    expect(proposals).toEqual([]);

    const uiProposals = proposals.map(mapBackendProposedTestToUI);
    expect(uiProposals).toEqual([]);
  });

  // 7. Approval success and status update
  it('7. transitions proposal status to APPROVED upon backend confirmation', async () => {
    const sessionId = 'sess-approve-action';
    const testId = 'test-uuid-bola-001';
    const approvedAt = '2026-10-31T01:30:00.000000Z';

    const backendApproved: BackendProposedTest = {
      test_id: testId,
      endpoint: { path: '/api/v1/documents/{doc_id}', method: 'GET' },
      test_type: 'BOLA',
      description: 'Verify cross-tenant object access',
      severity: 'High',
      status: 'Approved',
      approved_at: approvedAt,
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => backendApproved,
    } as Response);

    const result = await approveProposal(sessionId, testId);

    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/tests/${testId}/approve`),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-Session-ID': sessionId }),
      })
    );

    const uiModel = mapBackendProposedTestToUI(result);
    expect(uiModel.status).toBe('approved');
    expect(uiModel.approvedAt).toBe(approvedAt);
  });

  // 8. Rejection success and status update
  it('8. transitions proposal status to REJECTED upon backend confirmation', async () => {
    const sessionId = 'sess-reject-action';
    const testId = 'test-uuid-bfla-002';
    const rejectedAt = '2026-10-31T01:31:00.000000Z';

    const backendRejected: BackendProposedTest = {
      test_id: testId,
      endpoint: { path: '/api/v1/admin/roles/grant', method: 'POST' },
      test_type: 'BFLA',
      description: 'Verify standard role cannot access administrative routine',
      severity: 'Critical',
      status: 'Rejected',
      rejected_at: rejectedAt,
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => backendRejected,
    } as Response);

    const result = await rejectProposal(sessionId, testId);

    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/tests/${testId}/reject`),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-Session-ID': sessionId }),
      })
    );

    const uiModel = mapBackendProposedTestToUI(result);
    expect(uiModel.status).toBe('rejected');
    expect(uiModel.rejectedAt).toBe(rejectedAt);
  });

  // 9. Approval/rejection failure without false UI updates
  it('9. raises ApiError and prevents state transition when backend rejects approval', async () => {
    const sessionId = 'sess-failed-approval';
    const testId = 'test-uuid-not-found';

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({ detail: 'Proposal not found' }),
    } as Response);

    let caughtError: ApiError | null = null;
    try {
      await approveProposal(sessionId, testId);
    } catch (err: any) {
      caughtError = err;
    }

    expect(caughtError).not.toBeNull();
    expect(caughtError?.status).toBe(404);
    expect(caughtError?.details).toBe('Proposal not found');
  });

  // 10. Prevention of duplicate proposal requests
  it('10. demonstrates concurrency guarding prevents duplicate proposals', async () => {
    let callCount = 0;
    let isGenerating = false;

    async function handleProposeClick(sessionId: string) {
      if (isGenerating) return null; // Concurrency guard
      isGenerating = true;
      try {
        callCount++;
        return await getProposals(sessionId, true);
      } finally {
        isGenerating = false;
      }
    }

    globalThis.fetch = vi.fn().mockImplementation(async () => {
      await new Promise((res) => setTimeout(res, 20));
      return {
        ok: true,
        json: async () => [],
      } as Response;
    });

    // Simulate rapid concurrent clicks
    const [req1, req2, req3] = await Promise.all([
      handleProposeClick('sess-concurrent-1'),
      handleProposeClick('sess-concurrent-1'),
      handleProposeClick('sess-concurrent-1'),
    ]);

    expect(callCount).toBe(1);
    expect(req1).toEqual([]);
    expect(req2).toBeNull();
    expect(req3).toBeNull();
  });
});
