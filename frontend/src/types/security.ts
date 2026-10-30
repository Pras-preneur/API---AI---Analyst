export type FindingType = 
  | 'bola'
  | 'bfla'
  | 'mass_assignment'
  | 'information_disclosure'
  | 'excessive_data_exposure'
  | 'input_validation'
  | 'other';

export type EvidenceConfidence = 'low' | 'medium' | 'high';
export type ExposureType = 'internet_facing' | 'internal' | 'unknown';
export type DataSensitivity = 'public' | 'business' | 'personal' | 'sensitive' | 'unknown';
export type AuthRequired = 'true' | 'false' | 'unknown';
export type Exploitability = 'low' | 'medium' | 'high' | 'unknown';

export interface SecurityFindingInput {
  finding_id: string;
  scanner_verdict: string;
  finding_type: FindingType;
  evidence_confidence: EvidenceConfidence;
  exposure: ExposureType;
  data_sensitivity: DataSensitivity;
  auth_required: AuthRequired;
  exploitability: Exploitability;
  endpoint?: string;
  http_method?: string;
  evidence?: string;
  description?: string;
}

export interface LLMAnalysis {
  finding_summary?: string;
  evidence_assessment?: string;
  potential_impact?: string;
  priority_explanation?: string;
  remediation_steps?: string[];
  validation_steps?: string[];
  limitations?: string[];
  error?: string;
  details?: string;
}

export interface AnalysisResponse {
  finding_id: string;
  scanner_verdict: string;
  priority: 'P1' | 'P2' | 'P3' | string;
  priority_source: string;
  priority_probabilities: {
    P1?: number;
    P2?: number;
    P3?: number;
    [key: string]: number | undefined;
  };
  llm_analysis: LLMAnalysis;
  scanner_verdict_changed: boolean;
}

export interface FindingSummaryItem {
  id: string;
  finding_id: string;
  title: string;
  type: FindingType;
  scanner_verdict: string;
  ml_priority: 'P1' | 'P2' | 'P3';
  endpoint: string;
  http_method: string;
  timestamp: string;
  status: 'Open' | 'Remediated' | 'In Triage' | 'Under Review';
  data_sensitivity: DataSensitivity;
  exposure: ExposureType;
  confidence: EvidenceConfidence;
  finding_data: SecurityFindingInput;
}
