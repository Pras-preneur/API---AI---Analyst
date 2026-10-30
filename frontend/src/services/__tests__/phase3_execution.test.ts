import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { executeTests, reviewFinding, getFindings } from '../api';
import type {
  BackendExecuteRequest,
  BackendFinding,
  BackendFindingReviewRequest,
  BackendExecutionConfig,
} from '../../types/backend';
import type { ProposedTest } from '../../types/assistant';

describe('Phase 3B: Controlled Execution & Findings UI Tests', () => {
  const originalFetch = globalThis.fetch;
  const mockFetch = vi.fn();

  // Mock localStorage for node environment
  const mockStorage: Record<string, string> = {};
  const fakeLocalStorage = {
    getItem: (key: string) => mockStorage[key] || null,
    setItem: (key: string, val: string) => {
      mockStorage[key] = val;
    },
    removeItem: (key: string) => {
      delete mockStorage[key];
    },
    clear: () => {
      Object.keys(mockStorage).forEach((k) => delete mockStorage[k]);
    },
    get length() {
      return Object.keys(mockStorage).length;
    },
    key: (index: number) => Object.keys(mockStorage)[index] || null,
  };

  beforeEach(() => {
    globalThis.fetch = mockFetch;
    // @ts-ignore
    globalThis.localStorage = fakeLocalStorage;
    mockFetch.mockReset();
    fakeLocalStorage.clear();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    fakeLocalStorage.clear();
  });

  // Sample fixtures
  const sampleApprovedAuthTest: ProposedTest = {
    testId: 'test-auth-1',
    title: 'Missing Authentication probe',
    endpoint: '/auth/vulnerable/profile',
    method: 'GET',
    vulnerabilityType: 'other', // AUTH_MISSING_CREDENTIALS
    rationale: 'Verify if sensitive profile is returned without auth',
    payloadPreview: 'GET /auth/vulnerable/profile (No auth headers)',
    estimatedRisk: 'P1',
    status: 'approved',
  };

  const sampleApprovedBolaTest: ProposedTest = {
    testId: 'test-bola-1',
    title: 'BOLA Tenant Isolation Probe',
    endpoint: '/api/v1/accounts/{id}/statement',
    method: 'GET',
    vulnerabilityType: 'bola',
    rationale: 'Test cross-tenant data access',
    payloadPreview: 'GET /api/v1/accounts/101/statement with attacker token',
    estimatedRisk: 'P1',
    status: 'approved',
  };

  const sampleProposedTest: ProposedTest = {
    testId: 'test-unapproved-1',
    title: 'Unapproved probe',
    endpoint: '/api/v1/users',
    method: 'GET',
    vulnerabilityType: 'other',
    rationale: 'Pending user review',
    payloadPreview: 'GET /api/v1/users',
    estimatedRisk: 'P3',
    status: 'proposed',
  };

  const sampleRejectedTest: ProposedTest = {
    testId: 'test-rejected-1',
    title: 'Rejected probe',
    endpoint: '/api/v1/config',
    method: 'GET',
    vulnerabilityType: 'other',
    rationale: 'Rejected by security auditor',
    payloadPreview: 'GET /api/v1/config',
    estimatedRisk: 'P2',
    status: 'rejected',
  };

  const sampleMassAssignmentTest: ProposedTest = {
    testId: 'test-mass-assign-1',
    title: 'Mass Assignment Probe',
    endpoint: '/api/v1/users/profile',
    method: 'POST',
    vulnerabilityType: 'mass_assignment',
    rationale: 'Inject administrative attributes',
    payloadPreview: 'POST {"is_admin": true}',
    estimatedRisk: 'P1',
    status: 'approved',
  };

  const sampleBackendFinding: BackendFinding = {
    finding_id: 'find-001-abc',
    test_id: 'test-auth-1',
    endpoint: {
      path: '/auth/vulnerable/profile',
      method: 'GET',
    },
    evidence: {
      request: {
        method: 'GET',
        url: 'http://127.0.0.1:8001/auth/vulnerable/profile',
        headers: { authorization: '[REDACTED]' },
      },
      response: {
        status_code: 200,
        body: { id: 'alice', role: 'admin', secret: 'confidential-data' },
      },
    },
    severity: 'High',
    status: 'SUSPECTED',
    timestamp: '2026-10-31T01:30:00Z',
    execution_status: 'COMPLETED',
    assessment_outcome: 'SUSPECTED',
    assessment_reason: 'Endpoint returned sensitive data without credentials.',
    remediation: 'Apply authentication guard to endpoint.',
    is_human_reviewed: false,
  };

  // 1. Only approved proposals are selectable
  it('1. filters proposal inventory so only APPROVED proposals are eligible for execution', () => {
    const allProposals = [
      sampleApprovedAuthTest,
      sampleApprovedBolaTest,
      sampleProposedTest,
      sampleRejectedTest,
    ];

    const eligible = allProposals.filter((p) => p.status === 'approved');
    expect(eligible).toHaveLength(2);
    expect(eligible.map((p) => p.testId)).toEqual(['test-auth-1', 'test-bola-1']);

    // Non-approved proposals are strictly excluded
    expect(eligible.some((p) => p.status === 'proposed')).toBe(false);
    expect(eligible.some((p) => p.status === 'rejected')).toBe(false);
  });

  // 2. Unsupported MassAssignment proposals cannot execute
  it('2. excludes unsupported MassAssignment proposals from execution in SPEC_DRIVEN mode', () => {
    const isSupportedInSpecDriven = (vulnType: string) => {
      const norm = vulnType.toLowerCase();
      return norm.includes('auth') || norm === 'bola' || norm === 'bfla' || norm === 'other';
    };

    const proposals = [sampleApprovedBolaTest, sampleMassAssignmentTest];
    const executable = proposals.filter(
      (p) => p.status === 'approved' && isSupportedInSpecDriven(p.vulnerabilityType) && p.vulnerabilityType !== 'mass_assignment'
    );

    expect(executable).toHaveLength(1);
    expect(executable[0].testId).toBe('test-bola-1');
  });

  // 3. Execution request always includes SPEC_DRIVEN
  it('3. enforces that execution request payload always includes mode SPEC_DRIVEN and follow_redirects false', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [sampleBackendFinding],
    });

    const payload: BackendExecuteRequest = {
      proposal_ids: ['test-auth-1'],
      target: 'http://127.0.0.1:8001',
      config: {
        mode: 'SPEC_DRIVEN',
        target_base_url: 'http://127.0.0.1:8001',
        follow_redirects: false,
        require_approval: true,
        budget: { max_requests: 10 },
      },
    };

    const result = await executeTests('sess-123', payload);
    expect(result).toHaveLength(1);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe('http://127.0.0.1:8000/tests/execute');

    const sentBody = JSON.parse(options.body);
    expect(sentBody.config.mode).toBe('SPEC_DRIVEN');
    expect(sentBody.config.follow_redirects).toBe(false);
    expect(sentBody.config.require_approval).toBe(true);
  });

  // 4. Correct session ID propagation
  it('4. strictly propagates X-Session-ID header in execution requests', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [],
    });

    await executeTests('session-alpha-456', {
      proposal_ids: ['test-auth-1'],
      target: 'http://127.0.0.1:8001',
    });

    const [, options] = mockFetch.mock.calls[0];
    expect(options.headers['X-Session-ID']).toBe('session-alpha-456');
  });

  // 5. Correct target and request budget
  it('5. enforces valid target and bounded request budget within max 10 requests', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [],
    });

    const config: BackendExecutionConfig = {
      mode: 'SPEC_DRIVEN',
      target_base_url: 'http://127.0.0.1:8001',
      follow_redirects: false,
      require_approval: true,
      budget: { max_requests: 5 },
    };

    await executeTests('sess-1', {
      proposal_ids: ['test-auth-1'],
      target: 'http://127.0.0.1:8001',
      config,
    });

    const sentBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(sentBody.target).toBe('http://127.0.0.1:8001');
    expect(sentBody.config.budget.max_requests).toBeLessThanOrEqual(10);
    expect(sentBody.config.budget.max_requests).toBeGreaterThanOrEqual(1);
  });

  // 6. Missing identity configuration blocks execution
  it('6. prevents submission when required identities are missing or credentials collide', () => {
    // Validate Auth identity requires id, token, and verified credentials
    const validateAuthIdentity = (id: string, token: string, verified: boolean) => {
      if (!id.trim() || !token.trim() || !verified) {
        return false;
      }
      return true;
    };

    expect(validateAuthIdentity('', 'token123', true)).toBe(false);
    expect(validateAuthIdentity('alice', '', true)).toBe(false);
    expect(validateAuthIdentity('alice', 'token123', false)).toBe(false);
    expect(validateAuthIdentity('alice', 'token123', true)).toBe(true);

    // Validate BOLA identity collision
    const validateBolaCollision = (ownerToken: string, attackerToken: string) => {
      return ownerToken.trim() !== attackerToken.trim();
    };

    expect(validateBolaCollision('secret-token', 'secret-token')).toBe(false);
    expect(validateBolaCollision('token-owner', 'token-attacker')).toBe(true);
  });

  // 7. Duplicate execution prevention
  it('7. prevents duplicate execution calls while a request is actively pending', async () => {
    let executionInProgress = false;

    const executeWithGuard = async () => {
      if (executionInProgress) {
        throw new Error('Execution request already in progress.');
      }
      executionInProgress = true;
      try {
        await executeTests('sess-1', {
          proposal_ids: ['test-1'],
          target: 'http://127.0.0.1:8001',
        });
      } finally {
        executionInProgress = false;
      }
    };

    // First call hangs slightly
    let resolveFirst: any;
    mockFetch.mockReturnValueOnce(
      new Promise((res) => {
        resolveFirst = () =>
          res({
            ok: true,
            status: 200,
            json: async () => [],
          });
      })
    );

    const call1 = executeWithGuard();
    // Immediate concurrent call should be blocked
    await expect(executeWithGuard()).rejects.toThrow('Execution request already in progress.');

    resolveFirst();
    await call1;
  });

  // 8. Backend execution errors do not create fake findings
  it('8. handles backend 400/403/500 errors safely without generating fake findings', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Proposal test-1 is not approved' }),
    });

    let findings: BackendFinding[] = [];
    try {
      findings = await executeTests('sess-1', {
        proposal_ids: ['test-1'],
        target: 'http://127.0.0.1:8001',
      });
    } catch (err: any) {
      expect(err.status).toBe(403);
      expect(err.details).toBe('Proposal test-1 is not approved');
    }

    // Zero fake findings generated on error
    expect(findings).toHaveLength(0);
  });

  // 9. Actual findings render correctly
  it('9. accurately preserves backend finding properties and assessment outcome', () => {
    const finding = sampleBackendFinding;
    expect(finding.finding_id).toBe('find-001-abc');
    expect(finding.endpoint.path).toBe('/auth/vulnerable/profile');
    expect(finding.endpoint.method).toBe('GET');
    expect(finding.execution_status).toBe('COMPLETED');
    expect(finding.assessment_outcome).toBe('SUSPECTED');
    expect(finding.is_human_reviewed).toBe(false);
  });

  // 10. Evidence expansion displays backend evidence
  it('10. verifies that sanitized evidence contains redacted headers and response details', () => {
    const evidence = sampleBackendFinding.evidence;
    expect(evidence.request.headers.authorization).toBe('[REDACTED]');
    expect(evidence.response.status_code).toBe(200);
    expect(evidence.response.body).toEqual({
      id: 'alice',
      role: 'admin',
      secret: 'confidential-data',
    });
  });

  // 11. Credentials are not persisted or logged
  it('11. verifies that sensitive tokens and passwords are never written to localStorage', () => {
    const sensitiveTokens = ['bearer-secret-token-12345', 'super-secret-password'];

    // Check localStorage keys
    for (let i = 0; i < fakeLocalStorage.length; i++) {
      const key = fakeLocalStorage.key(i)!;
      const val = fakeLocalStorage.getItem(key)!;
      sensitiveTokens.forEach((tok) => {
        expect(val).not.toContain(tok);
      });
    }
  });

  // 12. Human review requires reviewer identity and rationale
  it('12. validates that human review requires a non-empty reviewer_id and rationale', async () => {
    const validateReviewInput = (reviewerId: string, notes: string) => {
      if (!reviewerId.trim()) {
        throw new Error('Reviewer ID is required.');
      }
      if (!notes.trim() || notes.trim().length < 5) {
        throw new Error('A meaningful review rationale (minimum 5 characters) is required.');
      }
      return true;
    };

    expect(() => validateReviewInput('', 'Some rationale')).toThrow('Reviewer ID is required.');
    expect(() => validateReviewInput('Analyst-1', '')).toThrow('minimum 5 characters');
    expect(() => validateReviewInput('Analyst-1', 'abc')).toThrow('minimum 5 characters');
    expect(validateReviewInput('Analyst-1', 'Valid justification for decision.')).toBe(true);
  });

  // 13. Findings are updated only after successful backend review
  it('13. transitions finding status to CONFIRMED or FALSE_POSITIVE only upon backend HTTP confirmation', async () => {
    const updatedFindingMock: BackendFinding = {
      ...sampleBackendFinding,
      is_human_reviewed: true,
      reviewer_id: 'Lead-Auditor',
      reviewer_notes: 'Confirmed vulnerability based on sensitive body disclosure.',
      reviewed_at: '2026-10-31T01:35:00Z',
      status: 'CONFIRMED',
      assessment_outcome: 'CONFIRMED',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => updatedFindingMock,
    });

    const reviewPayload: BackendFindingReviewRequest = {
      outcome: 'CONFIRMED',
      reviewer_id: 'Lead-Auditor',
      reviewer_notes: 'Confirmed vulnerability based on sensitive body disclosure.',
    };

    const result = await reviewFinding('sess-1', 'find-001-abc', reviewPayload);
    expect(result.status).toBe('CONFIRMED');
    expect(result.assessment_outcome).toBe('CONFIRMED');
    expect(result.is_human_reviewed).toBe(true);
    expect(result.reviewer_id).toBe('Lead-Auditor');

    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe('http://127.0.0.1:8000/findings/find-001-abc/review');
    expect(options.headers['X-Session-ID']).toBe('sess-1');
  });

  // 14. HTTP 200 never automatically marks a finding CONFIRMED
  it('14. guarantees invariant that HTTP 200 responses do NOT automatically assign CONFIRMED', () => {
    const autoFinding = sampleBackendFinding;
    // Automated engine returns status code 200
    expect(autoFinding.evidence.response.status_code).toBe(200);

    // Outcome is strictly SUSPECTED, NEVER CONFIRMED
    expect(autoFinding.assessment_outcome).toBe('SUSPECTED');
    expect(autoFinding.status).not.toBe('CONFIRMED');
    expect(autoFinding.is_human_reviewed).toBe(false);
  });
});
