/**
 * Verified Backend API Data Types
 * Matches schemas defined in API-Security-Assistant/app/models.py
 */

export interface BackendEndpointParameter {
  name: string;
  in: string;
  required?: boolean;
  schema?: Record<string, any>;
  description?: string;
}

export interface BackendEndpoint {
  path: string;
  method: string;
  summary?: string;
  description?: string;
  operation_id?: string;
  parameters?: BackendEndpointParameter[];
  security?: Array<Record<string, string[]>>;
  effective_security?: Array<Record<string, string[]>>;
  [key: string]: any;
}

export type BackendTestStatus = 'Proposed' | 'Approved' | 'Rejected' | 'Executed';

export interface BackendProposedTest {
  test_id: string;
  endpoint: BackendEndpoint;
  test_type: string;
  description: string;
  severity: string;
  status: BackendTestStatus;
  notes?: string;
  approved_at?: string;
  rejected_at?: string;
  executed_at?: string;
}

export interface BackendEvidence {
  request: Record<string, any>;
  response: Record<string, any>;
  notes?: string;
}

export type BackendAssessmentOutcome =
  | 'SUSPECTED'
  | 'INCONCLUSIVE'
  | 'ACCESS_DENIED'
  | 'CONFIRMED'
  | 'FALSE_POSITIVE';

export type BackendExecutionStatus = 'NOT_EXECUTED' | 'COMPLETED' | 'FAILED';

export interface BackendReviewRecord {
  record_id: string;
  reviewed_at: string;
  reviewer_id: string;
  decision: 'CONFIRMED' | 'FALSE_POSITIVE';
  notes?: string;
  previous_outcome?: string;
}

export interface BackendFinding {
  finding_id: string;
  test_id: string;
  endpoint: BackendEndpoint;
  evidence: BackendEvidence;
  severity: string;
  status: string;
  timestamp: string;
  notes?: string;
  execution_status?: BackendExecutionStatus;
  assessment_outcome?: BackendAssessmentOutcome;
  assessment_reason?: string;
  remediation?: string;
  is_human_reviewed: boolean;
  reviewed_at?: string;
  reviewer_id?: string;
  reviewer_notes?: string;
  review_history?: BackendReviewRecord[];
  requires_re_review?: boolean;
}

export interface BackendSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface BackendFindingDetail {
  finding_id: string;
  title: string;
  test_category: string;
  endpoint_path?: string;
  endpoint_method?: string;
  severity: string;
  status: string;
  evidence_summary: Record<string, any>;
  observed_behavior: string;
  recommended_remediation: string;
  limitations?: string;
  execution_status?: string;
  assessment_outcome?: string;
  assessment_reason?: string;
  is_human_reviewed: boolean;
  reviewer_id?: string;
  reviewed_at?: string;
  reviewer_notes?: string;
  requires_re_review: boolean;
  review_history: Array<Record<string, any>>;
}

export interface BackendReport {
  report_id: string;
  session_id: string;
  generated_at: string;
  target_base_url: string;
  assessment_summary: string;
  severity_counts: BackendSeverityCounts;
  finding_details: BackendFindingDetail[];
  not_executed_tests: string[];
  failed_tests: string[];
  scope_and_limitations: string;
  execution_statistics: Record<string, number>;
  pending_review_count: number;
}

export interface BackendExecuteRequest {
  proposal_ids: string[];
  target: string;
  config?: Record<string, any>;
}

export interface BackendReportRequest {
  target: string;
}

export interface BackendFindingReviewRequest {
  outcome: 'CONFIRMED' | 'FALSE_POSITIVE';
  reviewer_id: string;
  reviewer_notes?: string;
}

