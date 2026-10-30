import type { BackendFinding } from './backend';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';

export interface ApiEndpointParameter {
  name: string;
  in: 'path' | 'query' | 'header' | 'body' | 'cookie' | string;
  required: boolean;
  schemaType?: string;
  description?: string;
}

export interface ApiEndpoint {
  id: string;
  path: string;
  method: HttpMethod;
  summary: string;
  description?: string;
  authRequired: boolean;
  parameters: ApiEndpointParameter[];
  potentialRisks: string[];
}

export interface ApiSpec {
  id: string;
  title: string;
  version: string;
  description?: string;
  baseUrl: string;
  uploadedAt: string;
  endpoints: ApiEndpoint[];
  rawContent?: string;
  format: 'json' | 'yaml';
  sessionId?: string;
}

export type TestStatus = 'proposed' | 'approved' | 'rejected' | 'running' | 'completed' | 'failed';

export interface ProposedTest {
  testId: string;
  title: string;
  endpoint: string;
  method: HttpMethod;
  vulnerabilityType: 'bola' | 'bfla' | 'mass_assignment' | 'information_disclosure' | 'excessive_data_exposure' | 'input_validation' | 'other';
  rationale: string;
  payloadPreview: string;
  estimatedRisk: 'P1' | 'P2' | 'P3';
  status: TestStatus;
  approvedAt?: string;
  rejectedAt?: string;
  executionEvidence?: {
    httpStatus: number;
    responseSnippet: string;
    findingConfirmed: boolean;
    timestamp: string;
    details?: string;
  };
}

export interface SecurityFindingReportItem {
  id: string;
  title: string;
  endpoint: string;
  method: HttpMethod;
  vulnerabilityType: string;
  severity: 'P1' | 'P2' | 'P3';
  confidence: 'high' | 'medium' | 'low';
  scannerVerdict: string;
  evidence: string;
  impact: string;
  remediation: string[];
  validation: string[];
  isConfirmed: boolean;
}

export interface ReportOptionItem {
  id: string;
  label: string;
  format: string;
  description: string;
  icon?: string;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  specContext?: {
    specTitle: string;
    endpointCount: number;
  };
  proposedTests?: ProposedTest[];
  findings?: SecurityFindingReportItem[];
  backendFindings?: BackendFinding[];
  reportOptions?: ReportOptionItem[];
  codeBlock?: {
    language: string;
    code: string;
  };
}

export interface AssessmentReport {
  reportId: string;
  title: string;
  specTitle: string;
  generatedAt: string;
  summary: {
    totalEndpoints: number;
    testsProposed: number;
    testsExecuted: number;
    confirmedVulnerabilities: number;
    p1Count: number;
    p2Count: number;
    p3Count: number;
  };
  findings: SecurityFindingReportItem[];
  markdownContent: string;
}
