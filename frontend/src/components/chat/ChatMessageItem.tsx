import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Play,
  FileText,
} from 'lucide-react';
import type { ChatMessage } from '../../types/assistant';
import { MarkdownRenderer } from './MarkdownRenderer';

interface ChatMessageItemProps {
  message: ChatMessage;
  onApproveTest: (testId: string) => void;
  onRejectTest: (testId: string) => void;
  onSelectReportOption?: (optionId: string) => void;
  pendingTestIds?: Record<string, boolean>;
}

export const ChatMessageItem: React.FC<ChatMessageItemProps> = ({
  message,
  onApproveTest,
  onRejectTest,
  onSelectReportOption,
  pendingTestIds,
}) => {
  const isAssistant = message.sender === 'assistant';
  const [expandedTests, setExpandedTests] = useState<Record<string, boolean>>({});

  const toggleTestExpand = (testId: string) => {
    setExpandedTests((prev) => ({
      ...prev,
      [testId]: !prev[testId],
    }));
  };

  // If User Message: Vibrant pink/fuchsia bubble aligned to right
  if (!isAssistant) {
    return (
      <div className="py-1 px-1 sm:px-2 flex justify-end animate-in fade-in duration-200">
        <div className="max-w-md sm:max-w-lg flex flex-col items-end">
          <div className="bg-gradient-to-r from-pink-500 via-rose-500 to-pink-500 text-white rounded-2xl rounded-tr-xs px-3.5 py-2 text-xs sm:text-sm shadow-md shadow-pink-400/20 leading-relaxed font-sans select-text">
            {message.text}
          </div>
          <span className="text-[10px] text-slate-500 font-mono mt-0.5 pr-1">{message.timestamp}</span>
        </div>
      </div>
    );
  }

  // Assistant Message: Clean Glass bubble on left with mini iridescent orb avatar
  return (
    <div className="py-1.5 px-1 sm:px-2 flex justify-start animate-in fade-in duration-200 select-text">
      <div className="max-w-full flex items-start gap-2.5 w-full">
        {/* Mini Iridescent Avatar Orb */}
        <div
          className="w-7 h-7 rounded-full shrink-0 shadow-sm relative overflow-hidden mt-0.5"
          style={{
            background: `radial-gradient(circle at 35% 30%, #ffd6ea 0%, #ec4899 45%, #7c3aed 75%, #06b6d4 100%)`,
          }}
        >
          <div className="absolute inset-0 bg-white/20 mix-blend-overlay" />
          <div className="absolute top-0.5 left-1 w-1.5 h-1.5 rounded-full bg-white blur-[0.3px] opacity-90" />
        </div>

        {/* Message Card */}
        <div className="flex-1 space-y-2 min-w-0">
          <div className="bg-[#1a1e29]/95 backdrop-blur-md border border-slate-700/50 rounded-2xl rounded-tl-xs p-3.5 sm:p-4 shadow-[0_4px_20px_rgba(0,0,0,0.3)] text-slate-200 text-xs sm:text-sm leading-relaxed">
            
            {/* Header info */}
            <div className="flex items-center gap-2 mb-1.5 pb-1.5 border-b border-slate-700/50">
              <span className="font-semibold text-xs tracking-wide text-slate-200 flex items-center gap-1.5">
                <span>AI Security Analyst</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              </span>
              <span className="text-[10px] font-mono text-slate-500">• {message.timestamp}</span>

              {message.specContext && (
                <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded-full bg-pink-900/40 border border-pink-700/40 text-pink-300 font-medium truncate max-w-[140px]">
                  {message.specContext.specTitle}
                </span>
              )}
            </div>

            {/* Markdown Text */}
            <MarkdownRenderer content={message.text} />

            {/* Interactive Report Document Options */}
            {message.reportOptions && message.reportOptions.length > 0 && (
              <div className="mt-3 space-y-2 pt-2.5 border-t border-slate-700/50">
                <div className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-pink-500" />
                  <span>Choose Security Documentation Format to Prepare:</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {message.reportOptions.map((opt) => (
                    <button
                      key={opt.id}
                      onClick={() => onSelectReportOption?.(opt.id)}
                      className="text-left p-2.5 rounded-xl border border-slate-700/60 bg-[#161a24]/90 hover:bg-pink-900/20 hover:border-pink-600/50 transition-all shadow-xs group"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-xs text-slate-200 group-hover:text-pink-400 transition-colors">
                          {opt.label}
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-slate-800 text-slate-400">
                          {opt.format}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                        {opt.description}
                      </p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Embedded Human-in-the-Loop Proposed Tests */}
            {message.proposedTests && message.proposedTests.length > 0 && (
              <div className="mt-3 space-y-2 pt-2.5 border-t border-slate-700/50">
                <div className="flex items-center justify-between">
                  <div className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-pink-500" />
                    <span>Proposed Security Probes (Approval Required)</span>
                  </div>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-slate-100 text-slate-600">
                    Safe Non-Destructive
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-2">
                  {message.proposedTests.map((test) => {
                    const isExpanded = expandedTests[test.testId];
                    const isPending = Boolean(pendingTestIds?.[test.testId]);

                    return (
                      <div
                        key={test.testId}
                        className="rounded-xl border border-slate-700/60 bg-[#161a24]/95 p-2.5 shadow-xs hover:border-pink-600/50 transition-all text-xs"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span
                                className={`px-1.5 py-0.5 rounded-md text-[10px] font-mono font-bold ${
                                  test.method === 'GET'
                                    ? 'bg-blue-900/40 text-blue-400 border border-blue-700/50'
                                    : test.method === 'POST'
                                    ? 'bg-emerald-900/40 text-emerald-400 border border-emerald-700/50'
                                    : test.method === 'PUT'
                                    ? 'bg-amber-900/40 text-amber-400 border border-amber-700/50'
                                    : 'bg-rose-900/40 text-rose-400 border border-rose-700/50'
                                }`}
                              >
                                {test.method}
                              </span>
                              <span className="font-mono text-xs text-slate-200 font-semibold truncate max-w-[200px]">
                                {test.endpoint}
                              </span>
                              <span
                                className={`text-[9px] font-mono px-1.5 py-0.5 rounded-full font-bold ${
                                  test.estimatedRisk === 'P1'
                                    ? 'bg-rose-900/50 text-rose-400'
                                    : test.estimatedRisk === 'P2'
                                    ? 'bg-amber-900/50 text-amber-400'
                                    : 'bg-blue-900/50 text-blue-400'
                                }`}
                              >
                                ML {test.estimatedRisk}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-1 font-sans">{test.title}</p>
                          </div>

                          {/* Action Buttons */}
                          <div className="flex items-center gap-1 shrink-0">
                            {isPending ? (
                              <div className="px-2.5 py-0.5 rounded-full bg-slate-800 text-pink-300 text-[11px] font-mono flex items-center gap-1 border border-pink-700/40">
                                <span className="w-1.5 h-1.5 rounded-full bg-pink-400 animate-ping" />
                                <span>Updating...</span>
                              </div>
                            ) : test.status === 'proposed' ? (
                              <>
                                <button
                                  onClick={() => onApproveTest(test.testId)}
                                  className="px-2.5 py-1 rounded-full bg-gradient-to-r from-pink-500 to-rose-400 hover:opacity-90 text-white text-[11px] font-semibold shadow-xs flex items-center gap-1 transition-all active:scale-95"
                                  title="Approve proposed security probe"
                                >
                                  <Play className="w-2.5 h-2.5 fill-current" />
                                  <span>Approve</span>
                                </button>
                                <button
                                  onClick={() => onRejectTest(test.testId)}
                                  className="px-2 py-1 rounded-full bg-slate-800 hover:bg-slate-700 text-slate-400 text-[11px] font-medium transition-colors active:scale-95"
                                  title="Reject probe"
                                >
                                  Reject
                                </button>
                              </>
                            ) : null}

                            {test.status === 'approved' && (
                              <div className="px-2.5 py-0.5 rounded-full bg-pink-900/40 text-pink-300 text-[11px] font-medium flex items-center gap-1 border border-pink-700/50">
                                <CheckCircle2 className="w-3 h-3 text-pink-400" />
                                <span>Approved</span>
                              </div>
                            )}

                            {test.status === 'rejected' && (
                              <div className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-[11px] font-medium border border-slate-700/60 flex items-center gap-1">
                                <XCircle className="w-3 h-3 text-slate-500" />
                                <span>Rejected</span>
                              </div>
                            )}

                            {test.status === 'running' && (
                              <div className="px-2.5 py-0.5 rounded-full bg-sky-900/40 text-sky-400 text-[11px] font-mono flex items-center gap-1 border border-sky-700/50">
                                <span className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-ping" />
                                <span>Probing...</span>
                              </div>
                            )}

                            {test.status === 'completed' && (
                              <div className="px-2 py-0.5 rounded-full bg-emerald-900/40 text-emerald-400 text-[11px] font-medium flex items-center gap-1 border border-emerald-700/50">
                                <CheckCircle2 className="w-3 h-3" />
                                <span>Verified</span>
                              </div>
                            )}

                            <button
                              onClick={() => toggleTestExpand(test.testId)}
                              className="p-1 rounded text-slate-500 hover:text-slate-300 transition-colors"
                              title="Toggle details"
                            >
                              {isExpanded ? (
                                <ChevronUp className="w-3.5 h-3.5" />
                              ) : (
                                <ChevronDown className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>

                        {/* Expandable details */}
                        {isExpanded && (
                          <div className="mt-2 pt-2 border-t border-slate-700/50 space-y-1.5 text-[11px]">
                            <p className="text-slate-400">
                              <strong className="text-slate-300">Rationale: </strong>
                              {test.rationale}
                            </p>
                            <div className="bg-[#0d1017] rounded-lg p-2 font-mono text-[10px] text-slate-400 border border-slate-700/50 overflow-x-auto">
                              <code>{test.payloadPreview}</code>
                            </div>
                            {test.approvedAt && (
                              <div className="text-[10px] text-pink-300 font-mono">
                                Approved at: {new Date(test.approvedAt).toLocaleTimeString()}
                              </div>
                            )}
                            {test.rejectedAt && (
                              <div className="text-[10px] text-slate-400 font-mono">
                                Rejected at: {new Date(test.rejectedAt).toLocaleTimeString()}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Confirmed Findings Report Cards */}
            {message.findings && message.findings.length > 0 && (
              <div className="mt-3 space-y-2 pt-2.5 border-t border-slate-700/50">
                <div className="text-[11px] font-semibold text-rose-400 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Confirmed Security Findings ({message.findings.length})</span>
                </div>
                {message.findings.map((f) => (
                  <div
                    key={f.id}
                    className="p-2.5 rounded-xl bg-rose-900/20 border border-rose-700/40 text-xs text-rose-200 space-y-1"
                  >
                    <div className="flex items-center justify-between font-semibold">
                      <span className="font-mono text-[11px]">{f.vulnerabilityType.toUpperCase()} on {f.endpoint}</span>
                      <span className="px-1.5 py-0.2 rounded-full bg-rose-900/50 text-rose-400 text-[9px] font-mono">
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-rose-300/90 text-[11px]">{f.evidence}</p>
                    <p className="text-[10px] text-rose-400 font-mono"><strong>Remediation: </strong>{f.remediation}</p>
                  </div>
                ))}
              </div>
            )}

          </div>
        </div>
      </div>
    </div>
  );
};
