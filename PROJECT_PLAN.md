# Project Plan: API Security Testing Assistant

## 1. Project Overview & Product Vision
API Security Testing Assistant is a conversational, human-in-the-loop API security assessment platform.
Following evaluator feedback, the product is transitioning away from cluttered dashboard-style UIs to a **clean, Claude- and ChatGPT-inspired conversational interface** focused on:
- Interactive API documentation ingestion (OpenAPI/Swagger JSON & YAML).
- Human-in-the-loop security test proposals and explicit user approvals.
- High-precision vulnerability analysis and automated assessment reporting.
- Local Small Language Model (SLM) integration replacing external cloud LLMs (Nemotron) for fast, token-efficient, offline-capable analysis.

---

## 2. Implementation Phases

| Phase | Description | Status |
| :--- | :--- | :--- |
| **Phase 1** | Agree on architecture, chat-first UI structure, and API contracts | **In Progress** |
| **Phase 2** | Build clean chat layout and message composer (Claude/ChatGPT inspired) | Pending |
| **Phase 3** | Add OpenAPI/Swagger documentation upload & validation workflow | Pending |
| **Phase 4** | Build compact endpoint inventory view & parameter inspector | Pending |
| **Phase 5** | Implement Human-in-the-Loop test proposal cards with Approve/Reject lifecycle | Pending |
| **Phase 6** | Build findings and evidence presentation (confirmed vs unverified) | Pending |
| **Phase 7** | Add automated assessment report preview and download integration | Pending |
| **Phase 8** | SLM model training & integration replacing external Nemotron dependency | Pending |
| **Phase 9** | Responsive behavior, accessibility, and error state hardening | Pending |

---

## 3. Technology Stack & Frameworks

### Frontend
- **Framework**: React 19 + TypeScript + Vite 6
- **Styling**: Tailwind CSS (restrained, typography-first, Claude/ChatGPT inspired aesthetic)
- **Icons**: Lucide React
- **Markdown & Code Rendering**: GitHub-style markdown, syntax-highlighted code snippets
- **State Management**: Clean React state & custom service hooks with isolated mock fallbacks

### Backend
- **Framework**: FastAPI (Python 3.12, Uvicorn)
- **ML Triage Engine**: Scikit-Learn Classifier (`models/priority_model.joblib`) for P1/P2/P3 scoring
- **Security Logic**: OpenAPI spec parser, validation engine, test coordinator
- **SLM Engine**: Local domain-trained micro-model for token-efficient summarization & remediation

---

## 4. Frontend-to-Backend API Contracts

### A. Existing Endpoints
1. `GET /health`
   - Response: `{"status": "healthy"}`
2. `POST /api/v1/analyze`
   - Request: `SecurityFinding` (finding_id, scanner_verdict, finding_type, evidence_confidence, exposure, data_sensitivity, auth_required, exploitability, endpoint, http_method, evidence, description)
   - Response: Priority recommendation (`P1`, `P2`, `P3`), probability distribution, analysis summary, remediation steps, validation steps.

### B. Proposed Contract Extensions for Chat & Human-in-the-Loop

```typescript
// 1. Spec Upload & Parsing
POST /api/v1/spec/parse
Content-Type: multipart/form-data or application/json
Request: { file: File } or { content: string, format: 'json' | 'yaml' }
Response: {
  spec_id: string;
  title: string;
  version: string;
  base_url: string;
  endpoints_count: number;
  endpoints: Array<{
    id: string;
    path: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    summary: string;
    auth_required: boolean;
    parameters: Array<{ name: string; in: string; required: boolean; schema_type: string }>;
    potential_risks: string[]; // e.g., ["BOLA", "Mass Assignment"]
  }>;
}

// 2. Proposed Tests (Human-in-the-Loop)
POST /api/v1/tests/propose
Request: { spec_id: string; endpoint_id?: string; focus_areas?: string[] }
Response: {
  proposed_tests: Array<{
    test_id: string;
    title: string;
    endpoint: string;
    method: string;
    vulnerability_type: string;
    rationale: string;
    payload_preview: string;
    estimated_risk: 'LOW' | 'MEDIUM' | 'HIGH';
    status: 'proposed';
  }>;
}

// 3. Test Execution Approval
POST /api/v1/tests/execute
Request: { test_id: string; approved: boolean }
Response: {
  test_id: string;
  status: 'approved' | 'rejected' | 'running' | 'completed' | 'failed';
  execution_details?: {
    http_status_observed: number;
    response_snippet: string;
    finding_generated?: SecurityFinding;
  };
}

// 4. Report Generation
POST /api/v1/reports/generate
Request: { spec_id: string; test_ids: string[] }
Response: {
  report_id: string;
  summary: { total_tests: number; confirmed_vulnerabilities: number; p1_count: number; p2_count: number };
  download_url: string;
  markdown_content: string;
}
```

---

## 5. Local SLM Architecture (Replacing Nemotron)
- **Objective**: Zero dependency on external cloud LLM APIs, minimal token footprint, instant response latency (<100ms), and strict zero-hallucination compliance.
- **Components**:
  1. Fine-tuned/distilled lightweight model or local task-specific sequence generator for API security triage.
  2. Structured Prompt Encoder translating OpenAPI schemas + findings into compact token vectors.
  3. Deterministic guardrail layer ensuring scanner verdicts are strictly preserved and never tampered with.
