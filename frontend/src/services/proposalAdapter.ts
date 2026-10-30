/**
 * Proposal & Endpoint Adapter
 * Translates verified backend data contracts into frontend UI view models
 * without inventing fields or modifying backend state.
 */

import type {
  ApiSpec,
  ApiEndpoint,
  ProposedTest,
  HttpMethod,
} from '../types/assistant';
import type { BackendEndpoint, BackendProposedTest } from '../types/backend';

/**
 * Maps backend parsed endpoints into the frontend ApiSpec model.
 */
export function mapBackendEndpointsToSpec(
  backendEndpoints: BackendEndpoint[],
  specTitle: string,
  sessionId: string,
  rawContent?: string
): ApiSpec {
  let index = 1;
  const mappedEndpoints: ApiEndpoint[] = backendEndpoints.map((ep) => {
    const method = ep.method.toUpperCase() as HttpMethod;
    const parameters = (ep.parameters || []).map((p: any) => ({
      name: p.name || 'param',
      in: (p.location || p.in || 'query') as any,
      required: Boolean(p.required),
      schemaType: p.schema?.type || (typeof p.schema === 'string' ? p.schema : 'string'),
      description: p.description,
    }));

    const potentialRisks: string[] = [];
    if (ep.path.includes('{') || ep.path.includes('id') || ep.path.includes('user') || ep.path.includes('account')) {
      potentialRisks.push('BOLA / IDOR');
    }
    if (ep.path.includes('admin') || ep.path.includes('export') || ep.path.includes('manage') || ep.path.includes('role')) {
      potentialRisks.push('Broken Function Level Authorization (BFLA)');
    }
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      potentialRisks.push('Mass Assignment');
    }
    const hasAuth = Boolean(
      (ep.effective_security && ep.effective_security.length > 0) ||
      (ep.security && ep.security.length > 0)
    );
    if (hasAuth) {
      potentialRisks.push('Authentication Boundary');
    }
    if (potentialRisks.length === 0) {
      potentialRisks.push('API Inspection');
    }

    return {
      id: `ep-${index++}`,
      path: ep.path,
      method,
      summary: ep.summary || `${method} ${ep.path}`,
      description: ep.description || undefined,
      authRequired: hasAuth,
      parameters,
      potentialRisks,
    };
  });

  const cleanTitle = specTitle.replace(/\.[^/.]+$/, '').trim() || 'Uploaded API Specification';
  const format = specTitle.toLowerCase().endsWith('.json') ? 'json' : 'yaml';

  return {
    id: `spec-${sessionId}`,
    title: cleanTitle,
    version: '1.0.0',
    description: `OpenAPI specification parsed via backend session ${sessionId} (${mappedEndpoints.length} endpoints).`,
    baseUrl: 'http://127.0.0.1:8001',
    uploadedAt: 'Just now',
    endpoints: mappedEndpoints,
    rawContent,
    format,
    sessionId,
  };
}

/**
 * Maps a verified BackendProposedTest into the UI ProposedTest model.
 */
export function mapBackendProposedTestToUI(test: BackendProposedTest): ProposedTest {
  const method = (test.endpoint?.method || 'GET').toUpperCase() as HttpMethod;
  const path = test.endpoint?.path || '/';

  // Map backend test type to UI vulnerability vector
  let vulnerabilityType: ProposedTest['vulnerabilityType'] = 'other';
  const rawType = (test.test_type || '').toUpperCase();
  if (rawType.includes('BOLA')) {
    vulnerabilityType = 'bola';
  } else if (rawType.includes('BFLA')) {
    vulnerabilityType = 'bfla';
  } else if (rawType.includes('MASS')) {
    vulnerabilityType = 'mass_assignment';
  } else if (rawType.includes('EXCESSIVE') || rawType.includes('DATA')) {
    vulnerabilityType = 'excessive_data_exposure';
  } else if (rawType.includes('AUTH')) {
    vulnerabilityType = 'other';
  }

  // Map backend severity to ML estimated risk (P1/P2/P3)
  const sev = (test.severity || '').toLowerCase();
  let estimatedRisk: 'P1' | 'P2' | 'P3' = 'P3';
  if (sev === 'critical' || sev === 'high') {
    estimatedRisk = 'P1';
  } else if (sev === 'medium') {
    estimatedRisk = 'P2';
  } else {
    estimatedRisk = 'P3';
  }

  // Map backend status ('Proposed' | 'Approved' | 'Rejected' | 'Executed') to UI status
  let status: ProposedTest['status'] = 'proposed';
  const rawStatus = (test.status || '').toLowerCase();
  if (rawStatus === 'approved') {
    status = 'approved';
  } else if (rawStatus === 'rejected') {
    status = 'rejected';
  } else if (rawStatus === 'executed') {
    status = 'completed';
  }

  // Generate clear non-destructive payload assertion preview
  let payloadPreview = `${method} ${path}`;
  if (vulnerabilityType === 'bola') {
    payloadPreview = `${method} ${path.replace(/\{[^}]+\}/g, 'attacker_target_id')} -H "Authorization: Bearer <unprivileged_token>"`;
  } else if (vulnerabilityType === 'bfla') {
    payloadPreview = `${method} ${path} -H "Authorization: Bearer <standard_user_token>" (Assert HTTP 403 Forbidden)`;
  } else if (rawType.includes('AUTH') || rawType.includes('MISSING')) {
    payloadPreview = `${method} ${path} (Omit credentials; Assert HTTP 401 Unauthorized)`;
  } else if (vulnerabilityType === 'mass_assignment') {
    payloadPreview = `${method} ${path} -d '{"is_admin": true, "role": "admin"}'`;
  }

  return {
    testId: test.test_id,
    title: `${test.test_type}: ${method} ${path}`,
    endpoint: path,
    method,
    vulnerabilityType,
    rationale: test.description || `Security test probe for ${path}`,
    payloadPreview,
    estimatedRisk,
    status,
    approvedAt: test.approved_at,
    rejectedAt: test.rejected_at,
  };
}
