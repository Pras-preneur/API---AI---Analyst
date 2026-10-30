import React, { useState } from 'react';
import {
  ShieldAlert,
  X,
  Filter,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  ShieldCheck,
} from 'lucide-react';
import type { BackendFinding, BackendFindingReviewRequest } from '../../types/backend';
import { FindingEvidenceCard } from './FindingEvidenceCard';

interface FindingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  findings: BackendFinding[];
  onReviewFinding?: (findingId: string, review: BackendFindingReviewRequest) => Promise<void>;
  isReviewing?: boolean;
}

export const FindingsModal: React.FC<FindingsModalProps> = ({
  isOpen,
  onClose,
  findings,
  onReviewFinding,
  isReviewing = false,
}) => {
  const [filter, setFilter] = useState<string>('ALL');

  if (!isOpen) return null;

  const totalCount = findings.length;
  const suspectedCount = findings.filter((f) => f.assessment_outcome === 'SUSPECTED').length;
  const confirmedCount = findings.filter((f) => f.assessment_outcome === 'CONFIRMED').length;
  const fpCount = findings.filter((f) => f.assessment_outcome === 'FALSE_POSITIVE').length;
  const accessDeniedCount = findings.filter((f) => f.assessment_outcome === 'ACCESS_DENIED').length;
  const inconclusiveCount = findings.filter((f) => f.assessment_outcome === 'INCONCLUSIVE').length;

  const filteredFindings = findings.filter((f) => {
    if (filter === 'ALL') return true;
    return f.assessment_outcome === filter;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[92vh] bg-[#121622] border border-slate-700/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-200 font-sans">
        
        {/* Modal Header */}
        <div className="px-5 py-3.5 border-b border-slate-700/70 flex items-center justify-between bg-[#161a28]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-pink-900/40 border border-pink-700/60 flex items-center justify-center text-pink-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>Security Findings & Evidence Repository</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-pink-950 text-pink-300 border border-pink-800">
                  {totalCount} Findings
                </span>
              </h2>
              <p className="text-[11px] text-slate-400 font-mono">
                Sanitized Differential Probing Results • Human-in-the-Loop Governance
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 transition-colors"
            title="Close findings"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Filter Bar & Summary Counters */}
        <div className="px-5 py-2.5 border-b border-slate-800 bg-[#0e111a] flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1 mr-1">
              <Filter className="w-3 h-3" />
              <span>Filter:</span>
            </span>

            <button
              onClick={() => setFilter('ALL')}
              className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold transition-colors ${
                filter === 'ALL'
                  ? 'bg-pink-600 text-white'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({totalCount})
            </button>

            <button
              onClick={() => setFilter('SUSPECTED')}
              className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold transition-colors ${
                filter === 'SUSPECTED'
                  ? 'bg-amber-600 text-white'
                  : 'bg-slate-800 text-amber-400 hover:bg-slate-700'
              }`}
            >
              Suspected ({suspectedCount})
            </button>

            <button
              onClick={() => setFilter('CONFIRMED')}
              className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold transition-colors ${
                filter === 'CONFIRMED'
                  ? 'bg-rose-600 text-white'
                  : 'bg-slate-800 text-rose-400 hover:bg-slate-700'
              }`}
            >
              Confirmed ({confirmedCount})
            </button>

            <button
              onClick={() => setFilter('ACCESS_DENIED')}
              className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold transition-colors ${
                filter === 'ACCESS_DENIED'
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-emerald-400 hover:bg-slate-700'
              }`}
            >
              Access Denied ({accessDeniedCount})
            </button>

            <button
              onClick={() => setFilter('FALSE_POSITIVE')}
              className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold transition-colors ${
                filter === 'FALSE_POSITIVE'
                  ? 'bg-purple-600 text-white'
                  : 'bg-slate-800 text-purple-400 hover:bg-slate-700'
              }`}
            >
              False Positive ({fpCount})
            </button>

            <button
              onClick={() => setFilter('INCONCLUSIVE')}
              className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold transition-colors ${
                filter === 'INCONCLUSIVE'
                  ? 'bg-slate-700 text-white'
                  : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
            >
              Inconclusive ({inconclusiveCount})
            </button>
          </div>
        </div>

        {/* Scrollable Findings Cards */}
        <div className="flex-1 overflow-y-auto p-5 space-y-3.5">
          {filteredFindings.length === 0 ? (
            <div className="text-center py-12 space-y-2 text-slate-400">
              <CheckCircle2 className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-xs">No findings match the selected filter criteria.</p>
            </div>
          ) : (
            filteredFindings.map((finding) => (
              <FindingEvidenceCard
                key={finding.finding_id}
                finding={finding}
                onReview={onReviewFinding}
                isReviewing={isReviewing}
              />
            ))
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-5 py-3 border-t border-slate-700/80 bg-[#161a28] flex items-center justify-between text-xs text-slate-400">
          <span>
            Automated tools never confirm vulnerabilities; confirmation requires human auditor sign-off.
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
