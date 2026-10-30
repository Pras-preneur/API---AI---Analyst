/**
 * Frontend-to-Backend API Service Layer
 * Connects React UI to the verified FastAPI Security Assistant backend.
 * Default target: http://127.0.0.1:8000
 */

import type { SecurityFindingInput, AnalysisResponse } from '../types/security';
import type {
  BackendEndpoint,
  BackendProposedTest,
  BackendFinding,
  BackendReport,
  BackendExecuteRequest,
  BackendFindingReviewRequest,
} from '../types/backend';

export const API_BASE_URL: string =
  (import.meta.env?.VITE_API_URL as string | undefined)?.replace(/\/+$/, '') ||
  'http://127.0.0.1:8000';

export class ApiError extends Error {
  status: number;
  details?: string;

  constructor(message: string, status: number, details?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

/**
 * Extract error message or detail from a failed fetch response.
 */
async function parseErrorResponse(response: Response, fallbackMessage: string): Promise<ApiError> {
  let errorDetail = fallbackMessage;
  try {
    const errorJson = await response.json();
    if (typeof errorJson?.detail === 'string') {
      errorDetail = errorJson.detail;
    } else if (Array.isArray(errorJson?.detail)) {
      errorDetail = errorJson.detail.map((d: any) => d.msg || JSON.stringify(d)).join('; ');
    } else if (errorJson?.detail) {
      errorDetail = JSON.stringify(errorJson.detail);
    }
  } catch {
    try {
      const text = await response.text();
      if (text) errorDetail = text;
    } catch {
      // Ignore text decoding failure
    }
  }

  return new ApiError(
    `API Error (${response.status}): ${errorDetail}`,
    response.status,
    errorDetail
  );
}

// ============================================================================
// Phase 1 API Bridge Endpoints (Verified Backend)
// ============================================================================

/**
 * Health check endpoint
 * GET /health
 */
export async function checkHealth(baseUrl: string = API_BASE_URL): Promise<{ status: string; online: boolean }> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${baseUrl}/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      const statusStr = data.status || 'ok';
      return { status: statusStr, online: true };
    }
    return { status: 'unhealthy', online: false };
  } catch {
    return { status: 'offline', online: false };
  }
}

/**
 * Backward-compatible health check alias used across existing components.
 */
export async function checkBackendHealth(baseUrl: string = API_BASE_URL): Promise<{ status: string; online: boolean; message?: string }> {
  const result = await checkHealth(baseUrl);
  return {
    status: result.status,
    online: result.online,
    message: result.online ? 'Backend Connected' : 'Backend Disconnected',
  };
}

/**
 * Parse and upload an OpenAPI specification file.
 * POST /parse-openapi (multipart/form-data)
 * Returns the parsed endpoint inventory and the newly generated X-Session-ID.
 */
export async function uploadSpec(
  file: File | Blob,
  filename: string = 'openapi.yaml',
  baseUrl: string = API_BASE_URL
): Promise<{ endpoints: BackendEndpoint[]; sessionId: string }> {
  const formData = new FormData();
  formData.append('file', file, filename);

  const response = await fetch(`${baseUrl}/parse-openapi`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
    },
    body: formData,
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, 'Failed to parse and upload OpenAPI specification.');
  }

  const sessionId =
    response.headers.get('X-Session-ID') ||
    response.headers.get('x-session-id') ||
    '';

  if (!sessionId) {
    throw new ApiError(
      'Server parsed OpenAPI spec but did not return the required X-Session-ID header.',
      response.status,
      'Missing X-Session-ID header'
    );
  }

  const endpoints: BackendEndpoint[] = await response.json();
  return { endpoints, sessionId };
}

/**
 * Generate/retrieve security test proposals for a session.
 * POST /tests/propose?include_auth={includeAuth}
 * Header: X-Session-ID
 * If endpoints is omitted, backend uses the session's stored endpoint inventory.
 */
export async function getProposals(
  sessionId: string,
  includeAuth: boolean = true,
  endpoints?: BackendEndpoint[],
  baseUrl: string = API_BASE_URL
): Promise<BackendProposedTest[]> {
  if (!sessionId) {
    throw new ApiError('Session ID is required to fetch proposals.', 400);
  }

  const query = includeAuth ? '?include_auth=true' : '?include_auth=false';
  const url = `${baseUrl}/tests/propose${query}`;

  const headers: Record<string, string> = {
    'X-Session-ID': sessionId,
    Accept: 'application/json',
  };

  const options: RequestInit = {
    method: 'POST',
    headers,
  };

  if (endpoints && Array.isArray(endpoints) && endpoints.length > 0) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(endpoints);
  }

  const response = await fetch(url, options);

  if (!response.ok) {
    throw await parseErrorResponse(response, 'Failed to generate test proposals.');
  }

  return response.json();
}

/**
 * Retrieve a specific proposed test by ID.
 * GET /tests/{test_id}
 * Header: X-Session-ID
 */
export async function getProposal(
  sessionId: string,
  testId: string,
  baseUrl: string = API_BASE_URL
): Promise<BackendProposedTest> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!testId) throw new ApiError('Test ID is required.', 400);

  const response = await fetch(`${baseUrl}/tests/${testId}`, {
    method: 'GET',
    headers: {
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, `Failed to fetch proposal ${testId}.`);
  }

  return response.json();
}

/**
 * Approve a proposed test. Transition PROPOSED -> APPROVED.
 * POST /tests/{test_id}/approve
 * Header: X-Session-ID
 */
export async function approveProposal(
  sessionId: string,
  testId: string,
  baseUrl: string = API_BASE_URL
): Promise<BackendProposedTest> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!testId) throw new ApiError('Test ID is required.', 400);

  const response = await fetch(`${baseUrl}/tests/${testId}/approve`, {
    method: 'POST',
    headers: {
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, `Failed to approve proposal ${testId}.`);
  }

  return response.json();
}

/**
 * Reject a proposed test. Transition PROPOSED -> REJECTED.
 * POST /tests/{test_id}/reject
 * Header: X-Session-ID
 */
export async function rejectProposal(
  sessionId: string,
  testId: string,
  baseUrl: string = API_BASE_URL
): Promise<BackendProposedTest> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!testId) throw new ApiError('Test ID is required.', 400);

  const response = await fetch(`${baseUrl}/tests/${testId}/reject`, {
    method: 'POST',
    headers: {
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, `Failed to reject proposal ${testId}.`);
  }

  return response.json();
}

/**
 * Execute approved test proposals against the authorized local target.
 * POST /tests/execute
 * Header: X-Session-ID
 */
export async function executeTests(
  sessionId: string,
  payload: BackendExecuteRequest,
  baseUrl: string = API_BASE_URL
): Promise<BackendFinding[]> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!payload.proposal_ids || payload.proposal_ids.length === 0) {
    throw new ApiError('At least one proposal ID must be provided for execution.', 400);
  }
  if (!payload.target) {
    throw new ApiError('Execution target is required.', 400);
  }

  const response = await fetch(`${baseUrl}/tests/execute`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, 'Failed to execute approved proposals.');
  }

  return response.json();
}

/**
 * Retrieve all findings for a session.
 * GET /findings
 * Header: X-Session-ID
 */
export async function getFindings(
  sessionId: string,
  baseUrl: string = API_BASE_URL
): Promise<BackendFinding[]> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);

  const response = await fetch(`${baseUrl}/findings`, {
    method: 'GET',
    headers: {
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, 'Failed to fetch session findings.');
  }

  return response.json();
}

/**
 * Submit explicit human review for a finding.
 * POST /findings/{finding_id}/review
 * Header: X-Session-ID
 */
export async function reviewFinding(
  sessionId: string,
  findingId: string,
  review: BackendFindingReviewRequest,
  baseUrl: string = API_BASE_URL
): Promise<BackendFinding> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!findingId) throw new ApiError('Finding ID is required.', 400);

  const response = await fetch(`${baseUrl}/findings/${findingId}/review`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
    body: JSON.stringify(review),
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, `Failed to submit review for finding ${findingId}.`);
  }

  return response.json();
}

/**
 * Generate a security assessment report from findings stored for the session.
 * POST /reports
 * Header: X-Session-ID
 */
export async function createReport(
  sessionId: string,
  target: string,
  baseUrl: string = API_BASE_URL
): Promise<BackendReport> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!target) throw new ApiError('Target URL is required.', 400);

  const response = await fetch(`${baseUrl}/reports`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
    body: JSON.stringify({ target }),
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, 'Failed to generate security report.');
  }

  return response.json();
}

/**
 * Retrieve an in-memory security report by report ID.
 * GET /reports/{report_id}
 * Header: X-Session-ID
 */
export async function getReport(
  sessionId: string,
  reportId: string,
  baseUrl: string = API_BASE_URL
): Promise<BackendReport> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!reportId) throw new ApiError('Report ID is required.', 400);

  const response = await fetch(`${baseUrl}/reports/${reportId}`, {
    method: 'GET',
    headers: {
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, `Failed to fetch report ${reportId}.`);
  }

  return response.json();
}

// ============================================================================
/**
 * Download a styled PDF security assessment report from the backend.
 * GET /reports/{report_id}/pdf
 * Header: X-Session-ID
 */
export async function downloadReportPdf(
  sessionId: string,
  reportId: string,
  baseUrl: string = API_BASE_URL
): Promise<Blob> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!reportId) throw new ApiError('Report ID is required.', 400);

  const response = await fetch(`${baseUrl}/reports/${reportId}/pdf`, {
    method: 'GET',
    headers: {
      'X-Session-ID': sessionId,
    },
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, `Failed to download PDF for report ${reportId}.`);
  }

  return response.blob();
}

/**
 * Download a structured, evidence-sanitized JSON report from the backend.
 * GET /reports/{report_id}/json
 * Header: X-Session-ID
 */
export async function downloadReportJson(
  sessionId: string,
  reportId: string,
  baseUrl: string = API_BASE_URL
): Promise<Blob> {
  if (!sessionId) throw new ApiError('Session ID is required.', 400);
  if (!reportId) throw new ApiError('Report ID is required.', 400);

  const response = await fetch(`${baseUrl}/reports/${reportId}/json`, {
    method: 'GET',
    headers: {
      'X-Session-ID': sessionId,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, `Failed to download JSON for report ${reportId}.`);
  }

  return response.blob();
}

// Legacy / Advisory Functions (Preserved for existing workspace tabs)
// ============================================================================

/**
 * Perform security finding analysis against ML/AI service (advisory only).
 */
export async function analyzeFinding(
  payload: SecurityFindingInput,
  baseUrl: string = API_BASE_URL
): Promise<AnalysisResponse> {
  const sanitizedPayload: SecurityFindingInput = {
    ...payload,
    finding_type: payload.finding_type.toLowerCase() as any,
    evidence_confidence: payload.evidence_confidence.toLowerCase() as any,
    exposure: payload.exposure.toLowerCase() as any,
    data_sensitivity: payload.data_sensitivity.toLowerCase() as any,
    auth_required: payload.auth_required.toLowerCase() as any,
    exploitability: payload.exploitability.toLowerCase() as any,
  };

  const response = await fetch(`${baseUrl}/api/v1/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(sanitizedPayload),
  });

  if (!response.ok) {
    throw await parseErrorResponse(response, 'Analysis request failed.');
  }

  return response.json();
}

/**
 * Legacy report generation API call (preserved for existing UI modal).
 */
export async function generateSecurityReportAPI(
  reportType: string,
  specTitle: string = 'API Security Assessment',
  endpointsCount: number = 0,
  findings?: any[],
  context?: any,
  baseUrl: string = API_BASE_URL
): Promise<any> {
  const payload = {
    report_type: reportType,
    spec_title: specTitle,
    endpoints_count: endpointsCount,
    findings,
    context,
  };

  const res = await fetch(`${baseUrl}/api/v1/reports/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (res.ok) {
    const data = await res.json();
    return data.report;
  }

  throw new Error('Failed to generate report from backend.');
}
