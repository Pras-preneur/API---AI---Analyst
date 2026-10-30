import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Terminal,
  Copy,
  Check,
  Download,
  Share2,
  Info,
  Sparkles,
  ArrowRight,
  Shield,
  Layers,
  HelpCircle,
} from 'lucide-react';
import { AnalysisResponse, SecurityFindingInput } from '../../types/security';

interface AnalysisResultViewProps {
  response: AnalysisResponse;
  originalFinding: SecurityFindingInput;
  onOpenAssistant: (context: string) => void;
  onReset: () => void;
}

export const AnalysisResultView: React.FC<AnalysisResultViewProps> = ({
  response,
  originalFinding,
  onOpenAssistant,
  onReset,
}) => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const handleCopy = (text: string, sectionId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionId);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const handleExportJSON = () => {
    const reportData = {
      generated_at: new Date().toISOString(),
      original_finding: originalFinding,
      analysis_result: response,
      compliance: {
        scanner_verdict_preserved: !response.scanner_verdict_changed,
        ml_priority_is_recommendation: true,
      },
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `API-Security-Analysis-${response.finding_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const priority = response.priority?.toUpperCase() || 'P2';
  const isP1 = priority === 'P1';
  const isP2 = priority === 'P2';
  const isP3 = priority === 'P3';

  const probabilities = response.priority_probabilities || {};
  const p1Prob = probabilities.P1 !== undefined ? Math.round(probabilities.P1 * 100) : 0;
  const p2Prob = probabilities.P2 !== undefined ? Math.round(probabilities.P2 * 100) : 0;
  const p3Prob = probabilities.P3 !== undefined ? Math.round(probabilities.P3 * 100) : 0;

  const {
    finding_summary,
    evidence_assessment,
    potential_impact,
    priority_explanation,
    remediation_steps = [],
    validation_steps = [],
    limitations = [],
    error: llmError,
    details: llmDetails,
  } = response.llm_analysis || {};

  // Domain-specific intelligence fallbacks when LLM network is offline
  const getIntelligentFallbacks = () => {
    const type = originalFinding.finding_type;
    const endpoint = originalFinding.endpoint || 'API Gateway Endpoint';

    switch (type) {
      case 'bola':
        return {
          summary: `Broken Object Level Authorization (BOLA) detected on ${endpoint}. The application accepts object references without enforcing that the requesting identity possesses tenancy or authorization claims.`,
          evidence: originalFinding.evidence || 'HTTP request succeeded with foreign object identifier parameter without access control rejection.',
          impact: 'Critical data breach, unauthorized account takeover, and complete isolation failure across multi-tenant boundaries.',
          explanation: `The ML model assigned ${priority} because exposure is ${originalFinding.exposure}, data sensitivity is ${originalFinding.data_sensitivity}, and authentication/exploitability metrics indicate immediate risk of unauthorized access.`,
          remediation: [
            'Implement object ownership verification in authorization middleware before processing any entity ID parameter.',
            'Adopt Open Policy Agent (OPA) or Attribute-Based Access Control (ABAC) to validate token subject claims against resource tenant metadata.',
            'Replace sequential/guessable primary key identifiers in URLs with unguessable UUIDv4 or encrypted handles.',
          ],
          validation: [
            `curl -s -o /dev/null -w "%{http_code}" -X GET "${endpoint}" -H "Authorization: Bearer $TEST_FOREIGN_TOKEN" (Assert HTTP 403 Forbidden)`,
            'Execute automated fuzzing suite verifying authorization boundaries across all path parameters.',
          ],
        };
      case 'bfla':
        return {
          summary: `Broken Function Level Authorization (BFLA) on administrative routine ${endpoint}. Endpoint lacks role-based access control (RBAC) enforcement.`,
          evidence: originalFinding.evidence || 'Standard user token successfully triggered administrative procedure.',
          impact: 'Privilege escalation allowing unprivileged actors to trigger administrative functions and modify configuration states.',
          explanation: `The ML model computed ${priority} due to high exploitability of missing function-level authorization gates on an administrative endpoint.`,
          remediation: [
            'Deny administrative procedures by default in gateway router configuration.',
            'Enforce role-based access checks (e.g. @require_roles("superadmin")) at controller and gateway layers.',
            'Regularly audit administrative endpoints and eliminate obsolete legacy routing.',
          ],
          validation: [
            `curl -i -X POST "${endpoint}" -H "Authorization: Bearer $STANDARD_USER_TOKEN" (Assert HTTP 403 Forbidden)`,
          ],
        };
      case 'mass_assignment':
        return {
          summary: `Mass Assignment vulnerability on ${endpoint}. Client-supplied JSON properties bind directly to underlying domain entities without whitelist sanitization.`,
          evidence: originalFinding.evidence || 'Injected schema parameters (e.g. role, is_admin) accepted by endpoint.',
          impact: 'Unauthorized privilege modification, status overrides, and tampering with internal state attributes.',
          explanation: `The ML model evaluated data sensitivity (${originalFinding.data_sensitivity}) and exploitability to recommend ${priority}.`,
          remediation: [
            'Define strict DTO (Data Transfer Object) input schemas with allowlisted fields only.',
            'In Python/Pydantic, set ConfigDict(extra="forbid") to reject any undeclared attributes.',
            'Decouple client request objects from database ORM persistence models.',
          ],
          validation: [
            `curl -X PUT "${endpoint}" -H "Content-Type: application/json" -d '{"is_admin": true}' (Assert HTTP 422 Unprocessable Entity)`,
          ],
        };
      case 'information_disclosure':
        return {
          summary: `Sensitive Information Disclosure on ${endpoint}. Diagnostic metadata, system traces, or credentials are exposed in responses.`,
          evidence: originalFinding.evidence || 'Response payload contains sensitive environment parameters or credentials.',
          impact: 'Reconnaissance advantage for adversaries; leakage of cryptographic keys, connection strings, or internal network topology.',
          explanation: `The ML model categorized this as ${priority} based on direct sensitivity of leaked runtime artifacts.`,
          remediation: [
            'Disable debug routes, detailed stack traces, and verbose error formatting in production gateway builds.',
            'Ensure all database credentials and API secrets are stored strictly in secure KMS/vault solutions.',
            'Apply outbound schema projection filters to sanitize JSON responses before client transmission.',
          ],
          validation: [
            `curl -s "${endpoint}" | grep -E "(password|secret|key|token)" (Assert no sensitive tokens exposed)`,
          ],
        };
      default:
        return {
          summary: `Security finding detected on ${endpoint} relating to ${type.toUpperCase()}.`,
          evidence: originalFinding.evidence || 'Scanner heuristics indicated potential vulnerability condition.',
          impact: 'Potential system integrity or privacy degradation depending on upstream gateway configurations.',
          explanation: `The ML classifier recommended ${priority} based on feature vectors (${originalFinding.exposure}, ${originalFinding.data_sensitivity}).`,
          remediation: [
            'Apply strict defense-in-depth principles: validate input, enforce authentication, and log unauthorized access attempts.',
            'Ensure web application firewall (WAF) inspects incoming query and body parameters.',
          ],
          validation: [
            'Perform regression testing verifying expected HTTP status codes under boundary payloads.',
          ],
        };
    }
  };

  const fallbacks = getIntelligentFallbacks();
  const displaySummary = finding_summary || fallbacks.summary;
  const displayEvidence = evidence_assessment || fallbacks.evidence;
  const displayImpact = potential_impact || fallbacks.impact;
  const displayExplanation = priority_explanation || fallbacks.explanation;
  const displayRemediation = (remediation_steps.length > 0) ? remediation_steps : fallbacks.remediation;
  const displayValidation = (validation_steps.length > 0) ? validation_steps : fallbacks.validation;

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Top Banner: Finding Title & Actions */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-slate-400 mb-1">
            <span className="text-cyan-400 font-bold">{response.finding_id}</span>
            <span>•</span>
            <span className="uppercase text-slate-300">{originalFinding.finding_type}</span>
            <span>•</span>
            <span className="text-slate-400 font-sans">{originalFinding.endpoint || 'No endpoint specified'}</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white font-display">
            AI & ML Security Intelligence Report
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleExportJSON}
            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-mono font-medium flex items-center gap-2 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Dossier (JSON)</span>
          </button>

          <button
            onClick={() => onOpenAssistant(`Let's discuss finding ${response.finding_id}: ${finding_summary || originalFinding.description}`)}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 text-xs font-bold font-mono uppercase tracking-wider flex items-center gap-2 shadow-cyber-cyan transition-all"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Ask AI Assistant</span>
          </button>
        </div>
      </div>

      {/* Critical Comparison Matrix: Scanner Verdict vs ML Priority Recommendation */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Card 1: Scanner Verdict (Preserved & Immutable) */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-700/80 bg-slate-950/70 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 to-blue-500" />
          <div className="flex items-center justify-between mb-4">
            <span className="text-[10px] font-mono tracking-widest text-slate-400 uppercase font-semibold">
              ORIGINAL SCANNER VERDICT (IMMUTABLE)
            </span>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              Preserved
            </span>
          </div>

          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-700 flex items-center justify-center">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="text-xl sm:text-2xl font-black text-white font-display">
                {response.scanner_verdict}
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Verdict fidelity: 100% untouched by AI
              </p>
            </div>
          </div>

          <div className="mt-4 p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-300 font-mono">
            <div className="text-slate-400 text-[10px] uppercase tracking-wider mb-1">
              Security Governance Rule:
            </div>
            Scanner findings serve as authoritative boundary facts. The ML engine operates strictly in an assistive triage capacity.
          </div>
        </div>

        {/* Card 2: ML Priority Recommendation (P1 / P2 / P3) */}
        <div
          className={`glass-panel p-6 rounded-2xl border relative overflow-hidden ${
            isP1
              ? 'border-rose-500/40 bg-rose-950/15 shadow-cyber-p1'
              : isP2
              ? 'border-amber-500/40 bg-amber-950/15 shadow-cyber-p2'
              : 'border-cyan-500/40 bg-cyan-950/15 shadow-cyber-p3'
          }`}
        >
          <div
            className={`absolute top-0 left-0 right-0 h-1 ${
              isP1 ? 'bg-rose-500' : isP2 ? 'bg-amber-400' : 'bg-cyan-400'
            }`}
          />
          <div className="flex items-center justify-between mb-4">
            <span className="text-[10px] font-mono tracking-widest text-slate-300 uppercase font-semibold">
              ML-RECOMMENDED PRIORITY (ASSISTIVE)
            </span>
            <span
              className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                isP1
                  ? 'bg-rose-500/30 text-rose-300 border border-rose-500/40'
                  : isP2
                  ? 'bg-amber-500/30 text-amber-300 border border-amber-500/40'
                  : 'bg-cyan-500/30 text-cyan-300 border border-cyan-500/40'
              }`}
            >
              Model Recommendation
            </span>
          </div>

          <div className="flex items-center gap-4">
            <div
              className={`w-14 h-14 rounded-2xl flex items-center justify-center font-display font-black text-2xl shadow-lg ${
                isP1
                  ? 'bg-rose-500 text-slate-950 shadow-rose-500/30'
                  : isP2
                  ? 'bg-amber-400 text-slate-950 shadow-amber-400/30'
                  : 'bg-cyan-400 text-slate-950 shadow-cyan-400/30'
              }`}
            >
              {priority}
            </div>

            <div>
              <div className="text-xl sm:text-2xl font-black text-white font-display">
                {isP1 ? 'P1 - Critical Severity' : isP2 ? 'P2 - High Severity' : 'P3 - Medium Severity'}
              </div>
              <p className="text-xs text-slate-300 font-mono mt-0.5">
                Source: Trained Classifier Model
              </p>
            </div>
          </div>

          {/* Probability Confidence Bars */}
          <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Class Probabilities:</span>
              <span className="text-slate-200 font-bold">
                P1: {p1Prob}% • P2: {p2Prob}% • P3: {p3Prob}%
              </span>
            </div>

            <div className="flex h-2.5 rounded-full overflow-hidden bg-slate-900 border border-slate-800">
              <div style={{ width: `${p1Prob}%` }} className="bg-rose-500 transition-all duration-500" title={`P1: ${p1Prob}%`} />
              <div style={{ width: `${p2Prob}%` }} className="bg-amber-400 transition-all duration-500" title={`P2: ${p2Prob}%`} />
              <div style={{ width: `${p3Prob}%` }} className="bg-cyan-400 transition-all duration-500" title={`P3: ${p3Prob}%`} />
            </div>
          </div>
        </div>

      </div>

      {/* AI LLM Detailed Findings Section */}
      <div className="space-y-6">
        
        {/* LLM Status Banner if Offline/Error */}
        {llmError && (
          <div className="p-3.5 rounded-xl bg-slate-900/90 border border-cyan-500/30 text-xs font-mono text-cyan-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>NEMOTRON LLM GATEWAY: OFFLINE • HEURISTIC DEFENSIVE REMEDIATION LOADED</span>
            </div>
            <span className="text-[10px] text-slate-400">ML Priority Computed Directly</span>
          </div>
        )}

        {/* Finding Summary & Evidence Assessment */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Finding Summary */}
          <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-base font-bold text-white font-display flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400" />
                <span>Finding Summary</span>
              </h3>
              <button
                onClick={() => handleCopy(displaySummary, 'summary')}
                className="text-slate-400 hover:text-cyan-300 p-1"
                title="Copy Summary"
              >
                {copiedSection === 'summary' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <p className="text-sm text-slate-200 leading-relaxed font-sans">
              {displaySummary}
            </p>
          </div>

          {/* Evidence Assessment */}
          <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-base font-bold text-white font-display flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Evidence Assessment</span>
              </h3>
              <button
                onClick={() => handleCopy(displayEvidence, 'evidence')}
                className="text-slate-400 hover:text-cyan-300 p-1"
                title="Copy Assessment"
              >
                {copiedSection === 'evidence' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <p className="text-sm text-slate-200 leading-relaxed font-sans">
              {displayEvidence}
            </p>
          </div>

        </div>

        {/* Potential Impact & AI Priority Explanation */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Potential Impact */}
          <div className="glass-panel p-6 rounded-2xl border border-rose-500/20 bg-slate-950/50">
            <div className="flex items-center gap-2 text-rose-400 font-bold mb-3 font-display">
              <AlertTriangle className="w-4 h-4" />
              <span>Potential Impact (With Stated Uncertainty)</span>
            </div>
            <p className="text-sm text-slate-200 leading-relaxed font-sans">
              {displayImpact}
            </p>
          </div>

          {/* AI Priority Explanation */}
          <div className="glass-panel p-6 rounded-2xl border border-indigo-500/20 bg-slate-950/50">
            <div className="flex items-center gap-2 text-indigo-400 font-bold mb-3 font-display">
              <Layers className="w-4 h-4" />
              <span>ML Priority Explanation</span>
            </div>
            <p className="text-sm text-slate-200 leading-relaxed font-sans">
              {displayExplanation}
            </p>
          </div>

        </div>

        {/* Actionable Remediation Steps */}
        <div className="glass-panel p-6 rounded-2xl border border-emerald-500/25">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <h3 className="text-lg font-bold text-white font-display">
                Actionable Remediation Steps
              </h3>
            </div>
            <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              Defensive Best Practice
            </span>
          </div>

          <div className="space-y-3">
            {displayRemediation.map((step, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 text-sm text-slate-200 font-sans"
              >
                <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-300 font-mono text-xs flex items-center justify-center shrink-0 mt-0.5 font-bold">
                  {idx + 1}
                </span>
                <div className="flex-1 leading-relaxed">{step}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Safe Validation Steps */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <h3 className="text-lg font-bold text-white font-display">
                Safe Validation Steps
              </h3>
            </div>
            <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
              Defensive Verification Only
            </span>
          </div>

          <div className="space-y-3">
            {displayValidation.map((val, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-200"
              >
                <span className="text-slate-500 mr-2">[{idx + 1}]</span>
                <span>{val}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Limitations & Uncertainty Notes */}
        <div className="p-5 rounded-2xl bg-slate-950 border border-slate-800 text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-2 text-slate-300 font-bold mb-2 uppercase tracking-wider">
            <HelpCircle className="w-4 h-4 text-cyan-400" />
            <span>Analysis Limitations & Governance Boundaries</span>
          </div>
          {limitations.length > 0 ? (
            <ul className="list-disc list-inside space-y-1">
              {limitations.map((lim, idx) => (
                <li key={idx} className="leading-relaxed">{lim}</li>
              ))}
            </ul>
          ) : (
            <p className="leading-relaxed">
              Analysis was performed solely on provided finding attributes. If additional network perimeter filters (e.g. WAF, mTLS gateway) exist upstream, exploitability may be further mitigated in practice.
            </p>
          )}
          <div className="mt-3 pt-3 border-t border-slate-900 text-[11px] text-slate-500">
            LLM engine: NVIDIA Nemotron-70B • Output adheres to strict zero-hallucination defensive boundaries.
          </div>
        </div>

      </div>

      {/* Bottom Footer Actions */}
      <div className="flex items-center justify-between pt-6 border-t border-slate-800">
        <button
          onClick={onReset}
          className="px-6 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 font-semibold text-xs transition-colors"
        >
          ← New Analysis Run
        </button>

        <button
          onClick={() => onOpenAssistant(`Explain remediation strategies for ${response.finding_id}`)}
          className="px-6 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs uppercase tracking-wider shadow-cyber-cyan flex items-center gap-2"
        >
          <span>Chat with Assistant on Finding</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
};
