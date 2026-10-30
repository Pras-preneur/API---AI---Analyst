import type { SecurityFindingInput, AnalysisResponse } from '../types/security';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

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
 * Perform security finding analysis against FastAPI backend
 */
export async function analyzeFinding(payload: SecurityFindingInput): Promise<AnalysisResponse> {
  const sanitizedPayload: SecurityFindingInput = {
    ...payload,
    finding_type: payload.finding_type.toLowerCase() as any,
    evidence_confidence: payload.evidence_confidence.toLowerCase() as any,
    exposure: payload.exposure.toLowerCase() as any,
    data_sensitivity: payload.data_sensitivity.toLowerCase() as any,
    auth_required: payload.auth_required.toLowerCase() as any,
    exploitability: payload.exploitability.toLowerCase() as any,
  };

  const candidateUrls = [
    `${API_BASE_URL}/api/v1/analyze`,
    'http://127.0.0.1:8000/api/v1/analyze',
    'http://localhost:8000/api/v1/analyze',
  ];

  let lastError: any = null;

  for (const url of candidateUrls) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(sanitizedPayload),
      });

      if (!response.ok) {
        let errorDetail = 'Analysis request failed.';
        try {
          const errorJson = await response.json();
          errorDetail = errorJson.detail || errorDetail;
        } catch {
          errorDetail = await response.text();
        }

        if (response.status === 422) {
          throw new ApiError(`Validation Error: ${errorDetail}`, 422, errorDetail);
        } else if (response.status === 503) {
          throw new ApiError(`ML Model Unavailable: ${errorDetail}`, 503, errorDetail);
        } else {
          throw new ApiError(`Backend Error (${response.status}): ${errorDetail}`, response.status, errorDetail);
        }
      }

      const data: AnalysisResponse = await response.json();
      return data;
    } catch (err: any) {
      lastError = err;
      if (err instanceof ApiError && (err.status === 422 || err.status === 503)) {
        throw err;
      }
    }
  }

  throw lastError || new ApiError('Unable to connect to FastAPI backend at port 8000.', 0);
}

/**
 * Check if the backend is reachable
 */
export async function checkBackendHealth(): Promise<{ status: string; online: boolean; message?: string }> {
  const candidateUrls = [
    `${API_BASE_URL}/health`,
    'http://127.0.0.1:8000/health',
    'http://localhost:8000/health',
  ];

  for (const url of candidateUrls) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        return { status: data.status || 'healthy', online: true, message: 'ZYNORA SLM Online' };
      }
    } catch {
      // Continue
    }
  }

  return { status: 'offline', online: false, message: 'Backend Disconnected' };
}

/**
 * Request generation of a specific security documentation report
 */
export async function generateSecurityReportAPI(
  reportType: string,
  specTitle: string = 'FinTech Core Banking Gateway API',
  endpointsCount: number = 5,
  findings?: any[],
  context?: any
): Promise<any> {
  const candidateUrls = [
    `${API_BASE_URL}/api/v1/reports/generate`,
    'http://127.0.0.1:8000/api/v1/reports/generate',
    'http://localhost:8000/api/v1/reports/generate',
  ];

  const payload = {
    report_type: reportType,
    spec_title: specTitle,
    endpoints_count: endpointsCount,
    findings,
    context,
  };

  for (const url of candidateUrls) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data = await res.json();
        return data.report;
      }
    } catch {
      // Continue
    }
  }

  throw new Error('Failed to generate report from backend.');
}
