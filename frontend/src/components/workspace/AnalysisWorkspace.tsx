import React, { useState } from 'react';
import {
  Cpu,
  Sparkles,
  AlertCircle,
  RotateCcw,
  CheckCircle2,
  FileText,
  Terminal,
  Shield,
  Layers,
  Zap,
} from 'lucide-react';
import { SecurityFindingInput, AnalysisResponse, FindingType } from '../../types/security';
import { SAMPLE_TEMPLATES } from '../../data/mockData';
import { analyzeFinding, ApiError } from '../../services/api';
import { AnalysisResultView } from '../analysis/AnalysisResultView';

interface AnalysisWorkspaceProps {
  initialData?: SecurityFindingInput | null;
  onOpenAssistant: (context: string) => void;
}

export const AnalysisWorkspace: React.FC<AnalysisWorkspaceProps> = ({
  initialData,
  onOpenAssistant,
}) => {
  const defaultForm: SecurityFindingInput = initialData || SAMPLE_TEMPLATES[0].data;

  const [formData, setFormData] = useState<SecurityFindingInput>(defaultForm);
  const [selectedTemplateIndex, setSelectedTemplateIndex] = useState<number>(0);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Sync if initialData changes from Dashboard
  React.useEffect(() => {
    if (initialData) {
      setFormData(initialData);
      setAnalysisResult(null);
      setErrorMessage(null);
    }
  }, [initialData]);

  const handleTemplateSelect = (idx: number) => {
    setSelectedTemplateIndex(idx);
    setFormData(SAMPLE_TEMPLATES[idx].data);
    setErrorMessage(null);
  };

  const handleInputChange = (field: keyof SecurityFindingInput, value: any) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      const result = await analyzeFinding(formData);
      setAnalysisResult(result);
    } catch (err: any) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage(
          'Failed to communicate with FastAPI backend at http://127.0.0.1:8000. Ensure the server is running.'
        );
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReset = () => {
    setAnalysisResult(null);
    setErrorMessage(null);
  };

  if (analysisResult) {
    return (
      <AnalysisResultView
        response={analysisResult}
        originalFinding={formData}
        onOpenAssistant={onOpenAssistant}
        onReset={handleReset}
      />
    );
  }

  return (
    <div className="space-y-8">
      {/* Workspace Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-widest mb-1 font-bold">
            <Cpu className="w-4 h-4" />
            <span>Interactive Security Ingestion Pipeline</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-black text-white font-display">
            API SECURITY ANALYSIS WORKSPACE
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Submit scanner output and endpoint telemetry for real-time ML risk scoring and Nemotron AI remediation.
          </p>
        </div>

        {/* Template Quick Loader */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400 hidden sm:inline">Load Preset:</span>
          <select
            value={selectedTemplateIndex}
            onChange={(e) => handleTemplateSelect(Number(e.target.value))}
            className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-400 cursor-pointer"
          >
            {SAMPLE_TEMPLATES.map((tmpl, idx) => (
              <option key={idx} value={idx}>
                {tmpl.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Error Alert if request fails */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-500/40 text-rose-200 flex items-start gap-3 animate-in fade-in duration-200">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="text-xs font-mono">
            <div className="font-bold text-rose-300 uppercase tracking-wide">Analysis Request Failed</div>
            <div className="mt-1 text-rose-200 leading-relaxed">{errorMessage}</div>
            <div className="mt-2 text-slate-400">
              Target endpoint: <code className="text-cyan-300">POST /api/v1/analyze</code>
            </div>
          </div>
        </div>
      )}

      {/* Main Submission Form */}
      <form onSubmit={handleSubmit} className="space-y-8">
        
        {/* Section 1: Finding Core Identity */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15 space-y-5">
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase tracking-wider font-bold">
            <FileText className="w-4 h-4" />
            <span>1. Finding Identity & Scanner Verdict</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {/* Finding ID */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Finding ID <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                value={formData.finding_id}
                onChange={(e) => handleInputChange('finding_id', e.target.value)}
                placeholder="e.g. FIND-2024-BOLA-001"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-cyan-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-colors"
              />
            </div>

            {/* Scanner Verdict */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Scanner Verdict <span className="text-rose-400">*</span>
              </label>
              <select
                value={formData.scanner_verdict}
                onChange={(e) => handleInputChange('scanner_verdict', e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 transition-colors cursor-pointer"
              >
                <option value="Vulnerability Confirmed">Vulnerability Confirmed</option>
                <option value="Suspected">Suspected</option>
                <option value="False Positive">False Positive</option>
                <option value="Informational">Informational</option>
              </select>
            </div>

            {/* Finding Type */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Finding Type <span className="text-rose-400">*</span>
              </label>
              <select
                value={formData.finding_type}
                onChange={(e) => handleInputChange('finding_type', e.target.value as FindingType)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-400 transition-colors cursor-pointer"
              >
                <option value="bola">BOLA / IDOR (API1)</option>
                <option value="bfla">Broken Function Auth (API5)</option>
                <option value="mass_assignment">Mass Assignment (API6)</option>
                <option value="information_disclosure">Information Disclosure (API8)</option>
                <option value="excessive_data_exposure">Excessive Data Exposure (API3)</option>
                <option value="input_validation">Input Validation (API4)</option>
                <option value="other">Other</option>
              </select>
            </div>

            {/* Evidence Confidence */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Evidence Confidence <span className="text-rose-400">*</span>
              </label>
              <select
                value={formData.evidence_confidence}
                onChange={(e) => handleInputChange('evidence_confidence', e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 transition-colors cursor-pointer"
              >
                <option value="high">High (Reproducible)</option>
                <option value="medium">Medium (Partial Log)</option>
                <option value="low">Low (Heuristic Guess)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Section 2: Environmental & Exploitability Vectors */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15 space-y-5">
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase tracking-wider font-bold">
            <Layers className="w-4 h-4" />
            <span>2. Exposure, Sensitivity & Exploitability Parameters</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {/* Exposure */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Network Exposure <span className="text-rose-400">*</span>
              </label>
              <select
                value={formData.exposure}
                onChange={(e) => handleInputChange('exposure', e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 transition-colors cursor-pointer"
              >
                <option value="internet_facing">Internet-Facing (Public)</option>
                <option value="internal">Internal VPC Only</option>
                <option value="unknown">Unknown Perimeter</option>
              </select>
            </div>

            {/* Data Sensitivity */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Data Sensitivity <span className="text-rose-400">*</span>
              </label>
              <select
                value={formData.data_sensitivity}
                onChange={(e) => handleInputChange('data_sensitivity', e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 transition-colors cursor-pointer"
              >
                <option value="sensitive">Sensitive (PII, Financial, Secrets)</option>
                <option value="personal">Personal (User Profile, Email)</option>
                <option value="business">Business Proprietary</option>
                <option value="public">Public / Catalog</option>
                <option value="unknown">Unknown Sensitivity</option>
              </select>
            </div>

            {/* Authentication Required */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Auth Required <span className="text-rose-400">*</span>
              </label>
              <select
                value={formData.auth_required}
                onChange={(e) => handleInputChange('auth_required', e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 transition-colors cursor-pointer"
              >
                <option value="false">False (Unauthenticated Access)</option>
                <option value="true">True (Authenticated Token Needed)</option>
                <option value="unknown">Unknown Auth Layer</option>
              </select>
            </div>

            {/* Exploitability */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                Exploitability <span className="text-rose-400">*</span>
              </label>
              <select
                value={formData.exploitability}
                onChange={(e) => handleInputChange('exploitability', e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 transition-colors cursor-pointer"
              >
                <option value="high">High (Trivial, Zero Prerequisites)</option>
                <option value="medium">Medium (Requires Context / Valid Role)</option>
                <option value="low">Low (Difficult Chain / Timing)</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>
          </div>
        </div>

        {/* Section 3: Endpoint Telemetry & Payload Evidence */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15 space-y-5">
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase tracking-wider font-bold">
            <Terminal className="w-4 h-4" />
            <span>3. Endpoint Telemetry & Scanner Evidence</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* HTTP Method */}
            <div className="md:col-span-1">
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                HTTP Method
              </label>
              <select
                value={formData.http_method || 'GET'}
                onChange={(e) => handleInputChange('http_method', e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-400 cursor-pointer"
              >
                {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>

            {/* Endpoint Path */}
            <div className="md:col-span-2">
              <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
                API Endpoint URI
              </label>
              <input
                type="text"
                value={formData.endpoint || ''}
                onChange={(e) => handleInputChange('endpoint', e.target.value)}
                placeholder="/api/v2/users/{id}/financial-records"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-cyan-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-colors"
              />
            </div>
          </div>

          {/* Evidence */}
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
              Observed Scanner Evidence & Trace
            </label>
            <textarea
              rows={3}
              value={formData.evidence || ''}
              onChange={(e) => handleInputChange('evidence', e.target.value)}
              placeholder="e.g. HTTP 200 OK returned full record array for account ID 9928..."
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-colors leading-relaxed"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5 font-medium">
              Vulnerability Description & Engineering Notes
            </label>
            <textarea
              rows={2}
              value={formData.description || ''}
              onChange={(e) => handleInputChange('description', e.target.value)}
              placeholder="Describe the architectural failure or root cause..."
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700/80 text-xs font-sans text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-colors leading-relaxed"
            />
          </div>
        </div>

        {/* Submit Actions Strip */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-slate-800">
          <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Target: FastAPI Service • POST /api/v1/analyze</span>
          </div>

          <div className="flex items-center gap-4 w-full sm:w-auto">
            <button
              type="button"
              onClick={() => handleTemplateSelect(selectedTemplateIndex)}
              className="px-4 py-3 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs font-mono flex items-center gap-2 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Template</span>
            </button>

            <button
              type="submit"
              disabled={isSubmitting}
              className={`relative group px-8 py-3.5 rounded-xl font-bold font-display text-sm tracking-wider uppercase transition-all flex items-center justify-center gap-3 w-full sm:w-auto ${
                isSubmitting
                  ? 'bg-cyan-600/50 text-cyan-200 cursor-not-allowed'
                  : 'bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500 text-slate-950 hover:shadow-[0_0_30px_rgba(0,240,255,0.4)]'
              }`}
            >
              {isSubmitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  <span>ML & AI Triage Running...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 text-slate-950" />
                  <span>Analyze Finding</span>
                </>
              )}
            </button>
          </div>
        </div>

      </form>
    </div>
  );
};
