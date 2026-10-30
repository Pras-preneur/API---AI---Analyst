import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  UserCheck,
  Clock,
  ExternalLink,
} from 'lucide-react';
import type { BackendFinding, BackendFindingReviewRequest } from '../../types/backend';

interface FindingEvidenceCardProps {
  finding: BackendFinding;
  onReview?: (findingId: string, review: BackendFindingReviewRequest) => Promise<void>;
  isReviewing?: boolean;
}

export const FindingEvidenceCard: React.FC<FindingEvidenceCardProps> = ({
  finding,
  onReview,
  isReviewing = false,
}) => {
  const [evidenceExpanded, setEvidenceExpanded] = useState(false);
  const [reviewOpen, setReviewOpen] = useState(false);
  const [reviewOutcome, setReviewOutcome] = useState<'CONFIRMED' | 'FALSE_POSITIVE'>('CONFIRMED');
  const [reviewerId, setReviewerId] = useState('');
  const [reviewerNotes, setReviewerNotes] = useState('');
  const [reviewError, setReviewError] = useState<string | null>(null);

  const outcome = finding.assessment_outcome || 'INCONCLUSIVE';
  const execStatus = finding.execution_status || 'NOT_EXECUTED';
  const isCompleted = execStatus === 'COMPLETED';

  // Invariant: Backend rejects CONFIRMED if status is not COMPLETED or outcome is INCONCLUSIVE / ACCESS_DENIED
  const canConfirm =
    isCompleted &&
    outcome !== 'INCONCLUSIVE' &&
    outcome !== 'ACCESS_DENIED';

  const handleReviewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setReviewError(null);

    const trimmedReviewer = reviewerId.trim();
    const trimmedNotes = reviewerNotes.trim();

    if (!trimmedReviewer) {
      setReviewError('Reviewer ID is required for audit traceability.');
      return;
    }
    if (!trimmedNotes || trimmedNotes.length < 5) {
      setReviewError('A meaningful review rationale (minimum 5 characters) is required.');
      return;
    }
    if (reviewOutcome === 'CONFIRMED' && !canConfirm) {
      setReviewError(
        'Cannot confirm vulnerability: only COMPLETED tests with positive assessment evidence can be confirmed.'
      );
      return;
    }

    try {
      if (onReview) {
        await onReview(finding.finding_id, {
          outcome: reviewOutcome,
          reviewer_id: trimmedReviewer,
          reviewer_notes: trimmedNotes,
        });
        setReviewOpen(false);
        setReviewerNotes('');
      }
    } catch (err: any) {
      setReviewError(err?.message || 'Failed to submit human review.');
    }
  };

  // Outcome styling
  const renderOutcomeBadge = () => {
    switch (outcome) {
      case 'CONFIRMED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-950/80 text-rose-300 border border-rose-500/80 text-[11px] font-semibold font-mono">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>CONFIRMED VULNERABILITY</span>
          </span>
        );
      case 'SUSPECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-950/80 text-amber-300 border border-amber-500/80 text-[11px] font-semibold font-mono">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>SUSPECTED — Human Review Required</span>
          </span>
        );
      case 'ACCESS_DENIED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-500/80 text-[11px] font-semibold font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>ACCESS DENIED (Protected)</span>
          </span>
        );
      case 'FALSE_POSITIVE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-purple-950/80 text-purple-300 border border-purple-500/80 text-[11px] font-semibold font-mono">
            <CheckCircle2 className="w-3.5 h-3.5 text-purple-400" />
            <span>FALSE POSITIVE (Dismissed)</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-600/80 text-[11px] font-semibold font-mono">
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            <span>INCONCLUSIVE</span>
          </span>
        );
    }
  };

  const methodColor =
    finding.endpoint?.method === 'GET'
      ? 'bg-blue-900/50 text-blue-300 border-blue-700/60'
      : finding.endpoint?.method === 'POST'
      ? 'bg-emerald-900/50 text-emerald-300 border-emerald-700/60'
      : finding.endpoint?.method === 'PUT'
      ? 'bg-amber-900/50 text-amber-300 border-amber-700/60'
      : 'bg-rose-900/50 text-rose-300 border-rose-700/60';

  const reqData = finding.evidence?.request || {};
  const respData = finding.evidence?.response || {};

  return (
    <div className="rounded-xl border border-slate-700/70 bg-[#141823]/95 p-3.5 shadow-md space-y-3 text-xs text-slate-200">
      {/* 1. Header Bar: Method, Path, Status, Outcome */}
      <div className="flex items-start justify-between gap-2 flex-wrap">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`px-2 py-0.5 rounded-md text-[11px] font-mono font-bold border ${methodColor}`}>
              {finding.endpoint?.method || 'GET'}
            </span>
            <span className="font-mono text-sm font-semibold text-slate-100">
              {finding.endpoint?.path || 'Endpoint'}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
              {finding.severity || 'Medium'}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-pink-950/60 text-pink-300 border border-pink-800/50">
              {finding.notes?.includes('AUTH') || finding.assessment_reason?.includes('credential')
                ? 'AUTH_MISSING_CREDENTIALS'
                : 'SPEC_DRIVEN'}
            </span>
          </div>

          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
            <span>ID: <code className="text-slate-300">{finding.finding_id.slice(0, 8)}...</code></span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3 text-slate-500" />
              {finding.timestamp ? new Date(finding.timestamp).toLocaleTimeString() : 'Recent'}
            </span>
            <span>•</span>
            <span className={isCompleted ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
              Execution: {execStatus}
            </span>
          </div>
        </div>

        <div>{renderOutcomeBadge()}</div>
      </div>

      {/* 2. Assessment Reason / Remediation */}
      {finding.assessment_reason && (
        <div className="p-2.5 rounded-lg bg-[#0e121a] border border-slate-800 text-[11px] text-slate-300 font-sans leading-relaxed">
          <strong className="text-slate-200">Assessment: </strong>
          {finding.assessment_reason}
        </div>
      )}

      {finding.remediation && (
        <div className="p-2.5 rounded-lg bg-pink-950/20 border border-pink-900/40 text-[11px] text-pink-300/90 font-sans leading-relaxed">
          <strong className="text-pink-300 font-semibold">Remediation: </strong>
          {finding.remediation}
        </div>
      )}

      {/* 3. Sanitized Evidence Drawer */}
      <div className="border border-slate-800 rounded-lg overflow-hidden bg-[#0c0f16]">
        <button
          type="button"
          onClick={() => setEvidenceExpanded((prev) => !prev)}
          className="w-full flex items-center justify-between px-3 py-2 text-left text-[11px] font-mono text-slate-300 hover:text-pink-300 hover:bg-slate-800/40 transition-colors"
        >
          <span className="flex items-center gap-1.5 font-semibold">
            <ExternalLink className="w-3 h-3 text-pink-500" />
            <span>Sanitized Probing Evidence ({respData.status_code ? `HTTP ${respData.status_code}` : 'Evidence Captured'})</span>
          </span>
          {evidenceExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        {evidenceExpanded && (
          <div className="p-3 border-t border-slate-800 space-y-3 text-[11px]">
            {/* Request Evidence */}
            <div className="space-y-1">
              <span className="text-[10px] font-mono text-slate-400 font-semibold">SANITIZED REQUEST:</span>
              <div className="bg-[#080a0f] p-2.5 rounded border border-slate-800 font-mono text-[10px] space-y-1 overflow-x-auto text-slate-300">
                <div>
                  <span className="text-emerald-400 font-bold">{reqData.method || finding.endpoint?.method} </span>
                  <span className="text-slate-200">{reqData.url || `${finding.endpoint?.path}`}</span>
                </div>
                {reqData.headers && Object.keys(reqData.headers).length > 0 && (
                  <div className="pt-1 text-slate-400">
                    <div className="text-slate-500 font-semibold text-[9px]">HEADERS:</div>
                    {Object.entries(reqData.headers).map(([k, v]) => (
                      <div key={k}>
                        <span className="text-pink-400">{k}:</span>{' '}
                        <span className="text-slate-300">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                )}
                {reqData.body && (
                  <div className="pt-1 text-slate-400">
                    <div className="text-slate-500 font-semibold text-[9px]">BODY:</div>
                    <pre className="text-slate-300 whitespace-pre-wrap">{JSON.stringify(reqData.body, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>

            {/* Response Evidence */}
            <div className="space-y-1">
              <span className="text-[10px] font-mono text-slate-400 font-semibold">SANITIZED RESPONSE:</span>
              <div className="bg-[#080a0f] p-2.5 rounded border border-slate-800 font-mono text-[10px] space-y-1 overflow-x-auto">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Status:</span>
                  <span
                    className={`font-bold px-1.5 py-0.2 rounded text-[10px] ${
                      Number(respData.status_code) >= 200 && Number(respData.status_code) < 300
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : Number(respData.status_code) === 401 || Number(respData.status_code) === 403
                        ? 'bg-amber-950 text-amber-400 border border-amber-800'
                        : 'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}
                  >
                    HTTP {respData.status_code || 'N/A'}
                  </span>
                </div>

                {respData.body && (
                  <div className="pt-1">
                    <div className="text-slate-500 font-semibold text-[9px]">RESPONSE BODY (SANITIZED):</div>
                    <pre className="text-slate-300 text-[10px] max-h-48 overflow-y-auto whitespace-pre-wrap p-1.5 bg-[#05070a] rounded border border-slate-900">
                      {typeof respData.body === 'string'
                        ? respData.body
                        : JSON.stringify(respData.body, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 4. Human Review Audit Record or Action Section */}
      <div className="pt-2 border-t border-slate-800 flex items-center justify-between flex-wrap gap-2">
        {finding.is_human_reviewed ? (
          <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800/50 px-3 py-1.5 rounded-lg w-full">
            <UserCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <div className="flex-1 truncate">
              <span className="font-semibold">{finding.status}: </span>
              <span>Reviewed by <strong className="text-emerald-300">{finding.reviewer_id}</strong></span>
              {finding.reviewer_notes && (
                <span className="text-slate-400 block truncate">"{finding.reviewer_notes}"</span>
              )}
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-between w-full">
            <span className="text-[11px] font-mono text-amber-400/90 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
              <span>Pending Human Review</span>
            </span>

            {onReview && (
              <button
                type="button"
                onClick={() => setReviewOpen((prev) => !prev)}
                className="px-3 py-1 rounded-lg bg-pink-900/40 hover:bg-pink-900/70 border border-pink-700/60 text-pink-300 font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-xs"
              >
                <UserCheck className="w-3.5 h-3.5 text-pink-400" />
                <span>{reviewOpen ? 'Close Review' : 'Perform Human Review'}</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* 5. Human Review Form Modal/Drawer */}
      {reviewOpen && !finding.is_human_reviewed && (
        <form
          onSubmit={handleReviewSubmit}
          className="p-3.5 rounded-xl bg-[#0e121b] border border-pink-700/50 space-y-3 animate-in fade-in duration-200"
        >
          <div className="text-xs font-semibold text-pink-300 flex items-center justify-between">
            <span>Explicit Human Review Decision</span>
            <span className="text-[10px] font-mono text-slate-400">Audit Traceable</span>
          </div>

          {reviewError && (
            <div className="p-2 rounded bg-rose-950/80 border border-rose-700 text-[11px] text-rose-300">
              {reviewError}
            </div>
          )}

          {/* Decision Selector */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <label
              className={`p-2.5 rounded-lg border flex flex-col gap-1 cursor-pointer transition-all ${
                reviewOutcome === 'CONFIRMED'
                  ? 'bg-rose-950/60 border-rose-600 text-rose-200'
                  : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600'
              } ${!canConfirm ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name={`reviewOutcome-${finding.finding_id}`}
                  value="CONFIRMED"
                  checked={reviewOutcome === 'CONFIRMED'}
                  disabled={!canConfirm}
                  onChange={() => setReviewOutcome('CONFIRMED')}
                  className="accent-pink-500"
                />
                <span className="font-semibold text-rose-300">Confirm Vulnerability</span>
              </div>
              <span className="text-[10px] text-slate-400">
                {canConfirm
                  ? 'Verify verified security exposure based on evidence'
                  : 'Disabled: Inconclusive/Access Denied cannot be confirmed'}
              </span>
            </label>

            <label
              className={`p-2.5 rounded-lg border flex flex-col gap-1 cursor-pointer transition-all ${
                reviewOutcome === 'FALSE_POSITIVE'
                  ? 'bg-purple-950/60 border-purple-600 text-purple-200'
                  : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600'
              }`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name={`reviewOutcome-${finding.finding_id}`}
                  value="FALSE_POSITIVE"
                  checked={reviewOutcome === 'FALSE_POSITIVE'}
                  onChange={() => setReviewOutcome('FALSE_POSITIVE')}
                  className="accent-purple-500"
                />
                <span className="font-semibold text-purple-300">Mark False Positive</span>
              </div>
              <span className="text-[10px] text-slate-400">
                Dismiss finding due to legitimate application behavior
              </span>
            </label>
          </div>

          {/* Reviewer ID */}
          <div>
            <label className="block text-[11px] font-mono text-slate-300 mb-1">
              Reviewer Identity (e.g. your username or auditor ID) *
            </label>
            <input
              type="text"
              value={reviewerId}
              onChange={(e) => setReviewerId(e.target.value)}
              placeholder="e.g. SecAnalyst-Lead"
              className="w-full bg-[#161a24] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-pink-500 font-mono"
            />
          </div>

          {/* Rationale */}
          <div>
            <label className="block text-[11px] font-mono text-slate-300 mb-1">
              Review Rationale & Justification *
            </label>
            <textarea
              value={reviewerNotes}
              onChange={(e) => setReviewerNotes(e.target.value)}
              placeholder="Explain why this finding is confirmed or dismissed based on the sanitized evidence..."
              rows={2}
              className="w-full bg-[#161a24] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-pink-500"
            />
          </div>

          {/* Actions */}
          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={() => setReviewOpen(false)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isReviewing}
              className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-pink-500 to-rose-500 hover:opacity-95 text-white text-xs font-semibold shadow-xs disabled:opacity-50"
            >
              {isReviewing ? 'Submitting...' : 'Submit Human Decision'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
