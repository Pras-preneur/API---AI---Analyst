import React, { useState, useEffect } from 'react';
import { ClaudeSidebar } from './components/layout/ClaudeSidebar';
import { ChatMainView } from './components/chat/ChatMainView';
import { CoworkWorkspace } from './components/workspace/CoworkWorkspace';
import { SettingsCenter } from './components/settings/SettingsCenter';
import { SecurityDashboard } from './components/dashboard/SecurityDashboard';
import { AnalysisWorkspace } from './components/workspace/AnalysisWorkspace';
import { EndpointInventoryModal } from './components/chat/EndpointInventoryModal';
import { SpecUploadModal } from './components/chat/SpecUploadModal';
import { AssessmentReportModal } from './components/chat/AssessmentReportModal';
import type { WorkspaceView, ChatSession } from './types/workspace';
import type {
  ApiSpec,
  ApiEndpoint,
  ChatMessage,
  ProposedTest,
  SecurityFindingReportItem,
  AssessmentReport,
} from './types/assistant';
import type { SecurityFindingInput } from './types/security';
import { SAMPLE_SPECS } from './data/sampleSpecs';
import {
  sendChatMessageToSLM,
  generateTestProposals,
  executeApprovedTest,
  generateAssessmentReport,
} from './services/chatService';
import { checkBackendHealth } from './services/api';
import { Layers, ShieldAlert, FileDown, Plus, FileCode, CheckCircle2 } from 'lucide-react';

const INITIAL_GREETING: ChatMessage = {
  id: 'm-initial',
  sender: 'assistant',
  text:
    `Welcome to the **API Intelligence & Security Testing Assistant**.\n\n` +
    `I am your conversational, human-in-the-loop security testing copilot. I analyze OpenAPI specifications, ` +
    `propose non-destructive probe assertions, and evaluate risk using our trained ML priority classifier.\n\n` +
    `Preloaded **${SAMPLE_SPECS[0].title}** (${SAMPLE_SPECS[0].endpoints.length} endpoints). ` +
    `You can inspect inventory, run tests, or ask any question.`,
  timestamp: 'Just now',
  specContext: {
    specTitle: SAMPLE_SPECS[0].title,
    endpointCount: SAMPLE_SPECS[0].endpoints.length,
  },
  proposedTests: generateTestProposals(SAMPLE_SPECS[0]),
};

const DEFAULT_SESSIONS: ChatSession[] = [
  {
    id: 'session-default-1',
    title: 'FinTech Banking API Audit',
    createdAt: Date.now() - 3600000,
    updatedAt: Date.now() - 1800000,
    messages: [],
    specId: SAMPLE_SPECS[0].id,
  },
  {
    id: 'session-default-2',
    title: 'BOLA Tenant Isolation Review',
    createdAt: Date.now() - 86400000,
    updatedAt: Date.now() - 82000000,
    messages: [
      {
        id: 'm-1',
        sender: 'user',
        text: 'Verify tenant isolation and BOLA risks on customer account statement endpoints',
        timestamp: 'Yesterday',
      },
      {
        id: 'm-2',
        sender: 'assistant',
        text: 'Formulated non-destructive tenancy verification probes for `/api/v1/accounts/{id}/statement`. Evaluated risk as **P1 High Priority**.',
        timestamp: 'Yesterday',
      },
    ],
    specId: SAMPLE_SPECS[0].id,
  },
];

export function App() {
  const [activeView, setActiveView] = useState<WorkspaceView>('chat');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Specifications
  const [specs, setSpecs] = useState<ApiSpec[]>(SAMPLE_SPECS);
  const [activeSpec, setActiveSpec] = useState<ApiSpec | null>(SAMPLE_SPECS[0]);
  const [backendOnline, setBackendOnline] = useState(false);

  // Sessions Store (Persistent with localStorage)
  const [sessions, setSessions] = useState<ChatSession[]>(() => {
    try {
      const stored = localStorage.getItem('zynora_chat_sessions_v4');
      if (stored) return JSON.parse(stored);
    } catch {
      // Fallback
    }
    return DEFAULT_SESSIONS;
  });

  const [activeSessionId, setActiveSessionId] = useState<string>(sessions[0]?.id || 'session-default-1');

  // Active Session Messages
  const currentSession = sessions.find((s) => s.id === activeSessionId) || sessions[0];
  const [messages, setMessages] = useState<ChatMessage[]>(currentSession ? currentSession.messages : []);
  const [isLoading, setIsLoading] = useState(false);

  // Modals
  const [inventoryOpen, setInventoryOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [currentReport, setCurrentReport] = useState<AssessmentReport | null>(null);

  // Save sessions to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('zynora_chat_sessions_v4', JSON.stringify(sessions));
    } catch {
      // Storage quota or sandboxed
    }
  }, [sessions]);

  // Sync messages when active session changes
  useEffect(() => {
    const session = sessions.find((s) => s.id === activeSessionId);
    setMessages(session ? session.messages : []);
  }, [activeSessionId]);

  // Check Backend Health periodically
  useEffect(() => {
    let mounted = true;
    const testHealth = async () => {
      const res = await checkBackendHealth();
      if (mounted) setBackendOnline(res.online);
    };
    testHealth();
    const interval = setInterval(testHealth, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  // Update current session messages in session store
  const updateCurrentSessionMessages = (newMessages: ChatMessage[], targetId: string = activeSessionId) => {
    setMessages(newMessages);
    setSessions((prev) =>
      prev.map((s) =>
        s.id === targetId
          ? { ...s, messages: newMessages, updatedAt: Date.now() }
          : s
      )
    );
  };

  // Create New Chat
  const handleNewChat = () => {
    const newId = `session-${Date.now()}`;
    const newSession: ChatSession = {
      id: newId,
      title: 'New Security Session',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      messages: [],
      specId: activeSpec?.id,
    };

    setSessions((prev) => [newSession, ...prev]);
    setActiveSessionId(newId);
    setMessages([]); // Clears messages immediately so the new chat starts fresh!
    setActiveView('chat');
  };

  const handleSelectSession = (sessionId: string) => {
    setActiveSessionId(sessionId);
    const session = sessions.find((s) => s.id === sessionId);
    setMessages(session ? session.messages : []);
    setActiveView('chat');
  };

  const handleRenameSession = (sessionId: string, newTitle: string) => {
    setSessions((prev) =>
      prev.map((s) => (s.id === sessionId ? { ...s, title: newTitle } : s))
    );
  };

  const handleDeleteSession = (sessionId: string) => {
    setSessions((prev) => {
      const filtered = prev.filter((s) => s.id !== sessionId);
      if (activeSessionId === sessionId) {
        if (filtered.length > 0) {
          setActiveSessionId(filtered[0].id);
          setMessages(filtered[0].messages);
        } else {
          const freshId = `session-${Date.now()}`;
          const freshSession: ChatSession = {
            id: freshId,
            title: 'New Security Session',
            createdAt: Date.now(),
            updatedAt: Date.now(),
            messages: [],
            specId: activeSpec?.id,
          };
          setActiveSessionId(freshId);
          setMessages([]);
          return [freshSession];
        }
      }
      return filtered;
    });
  };

  const handleArchiveSession = (sessionId: string) => {
    setSessions((prev) =>
      prev.map((s) => (s.id === sessionId ? { ...s, isArchived: true } : s))
    );
  };

  // Spec upload & selection
  const handleSpecLoaded = (newSpec: ApiSpec) => {
    setSpecs((prev) => [newSpec, ...prev]);
    setActiveSpec(newSpec);
    const initialTests = generateTestProposals(newSpec);

    const switchMsg: ChatMessage = {
      id: `m-${Date.now()}`,
      sender: 'assistant',
      text:
        `Uploaded and parsed specification **${newSpec.title}** (v${newSpec.version}). ` +
        `Cataloged **${newSpec.endpoints.length} endpoints**. Ready for security probes.`,
      timestamp: 'Just now',
      specContext: {
        specTitle: newSpec.title,
        endpointCount: newSpec.endpoints.length,
      },
      proposedTests: initialTests,
    };

    updateCurrentSessionMessages([...messages, switchMsg]);
    setActiveView('chat');
  };

  // Send message
  const handleSendMessage = async (text: string) => {
    const targetSessionId = activeSessionId;

    if (text.toLowerCase().includes('report') || text.toLowerCase().includes('export')) {
      handleOpenReport();
      return;
    }

    const userMsg: ChatMessage = {
      id: `m-${Date.now()}`,
      sender: 'user',
      text,
      timestamp: 'Just now',
    };

    // Grab current session messages directly to avoid stale closures
    const activeSessionData = sessions.find((s) => s.id === targetSessionId);
    const baseMessages = activeSessionData ? activeSessionData.messages : messages;
    const updated = [...baseMessages, userMsg];

    setMessages(updated);
    setSessions((prev) =>
      prev.map((s) =>
        s.id === targetSessionId
          ? {
              ...s,
              title: s.messages.length === 0 ? (text.slice(0, 26) + (text.length > 26 ? '...' : '')) : s.title,
              messages: updated,
              updatedAt: Date.now(),
            }
          : s
      )
    );

    setIsLoading(true);

    try {
      const slmResult = await sendChatMessageToSLM(text, {
        specTitle: activeSpec?.title,
        endpointCount: activeSpec?.endpoints.length,
      });

      let proposedTests: ProposedTest[] | undefined;
      if (
        (text.toLowerCase().includes('test') ||
          text.toLowerCase().includes('propose') ||
          text.toLowerCase().includes('scan') ||
          text.toLowerCase().includes('audit') ||
          text.toLowerCase().includes('bola')) &&
        activeSpec
      ) {
        proposedTests = generateTestProposals(activeSpec);
      }

      const assistantMsg: ChatMessage = {
        id: `m-${Date.now() + 1}`,
        sender: 'assistant',
        text: typeof slmResult === 'string' ? slmResult : slmResult.reply,
        timestamp: 'Just now',
        proposedTests,
        reportOptions: typeof slmResult === 'object' ? slmResult.reportOptions : undefined,
      };

      const finalMessages = [...updated, assistantMsg];
      setMessages(finalMessages);
      setSessions((prev) =>
        prev.map((s) =>
          s.id === targetSessionId
            ? { ...s, messages: finalMessages, updatedAt: Date.now() }
            : s
        )
      );
    } catch {
      const errorMsg: ChatMessage = {
        id: `m-${Date.now() + 1}`,
        sender: 'assistant',
        text: 'Local SLM engine offline or initializing. Running simulated security heuristics.',
        timestamp: 'Just now',
      };
      const finalMessages = [...updated, errorMsg];
      setMessages(finalMessages);
      setSessions((prev) =>
        prev.map((s) =>
          s.id === targetSessionId
            ? { ...s, messages: finalMessages, updatedAt: Date.now() }
            : s
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Approve test
  const handleApproveTest = async (testId: string) => {
    // 1. Mark running
    const runningList = messages.map((msg) => {
      if (!msg.proposedTests) return msg;
      return {
        ...msg,
        proposedTests: msg.proposedTests.map((t) =>
          t.testId === testId ? { ...t, status: 'running' as const } : t
        ),
      };
    });
    updateCurrentSessionMessages(runningList);

    // 2. Find and execute test
    let targetTest: ProposedTest | undefined;
    for (const m of messages) {
      targetTest = m.proposedTests?.find((t) => t.testId === testId);
      if (targetTest) break;
    }

    if (!targetTest) return;

    const { updatedTest, finding } = await executeApprovedTest(targetTest);

    // 3. Update completed test
    const completedList = runningList.map((msg) => {
      if (!msg.proposedTests) return msg;
      return {
        ...msg,
        proposedTests: msg.proposedTests.map((t) =>
          t.testId === testId ? updatedTest : t
        ),
        findings: finding ? [...(msg.findings || []), finding] : msg.findings,
      };
    });

    const replyMsg: ChatMessage = {
      id: `m-${Date.now()}`,
      sender: 'assistant',
      text: finding
        ? `### Test Execution Complete: Defect Replicated\n\n` +
          `The probe assertion on \`${targetTest.method} ${targetTest.endpoint}\` completed with **HTTP 200 OK**. ` +
          `Our trained ML priority model evaluated the vector and recommended **${finding.severity}**. ` +
          `Detailed evidence and defensive remediation steps have been recorded below.`
        : `### Test Execution Complete: Defense Verified\n\n` +
          `The target endpoint \`${targetTest.method} ${targetTest.endpoint}\` defended against the probe assertion ` +
          `with HTTP 403 Forbidden. Tenancy isolation verified for this vector.`,
      timestamp: 'Just now',
      findings: finding ? [finding] : undefined,
    };

    updateCurrentSessionMessages([...completedList, replyMsg]);
  };

  // Reject test
  const handleRejectTest = (testId: string) => {
    const updated = messages.map((msg) => {
      if (!msg.proposedTests) return msg;
      return {
        ...msg,
        proposedTests: msg.proposedTests.map((t) =>
          t.testId === testId ? { ...t, status: 'rejected' as const } : t
        ),
      };
    });
    updateCurrentSessionMessages(updated);
  };

  // Open Report Modal
  const handleOpenReport = () => {
    if (!activeSpec) return;
    const allTests: ProposedTest[] = [];
    const allFindings: SecurityFindingReportItem[] = [];

    messages.forEach((m) => {
      if (m.proposedTests) allTests.push(...m.proposedTests);
      if (m.findings) allFindings.push(...m.findings);
    });

    const report = generateAssessmentReport(activeSpec, allTests, allFindings);
    setCurrentReport(report);
    setReportOpen(true);
  };

  return (
    <div className="relative w-screen h-screen flex items-center justify-center p-1 sm:p-2.5 md:p-3.5 bg-gradient-to-br from-[#05060a] via-[#0b0e15] to-[#13161e] overflow-hidden select-none font-sans">
      
      {/* Decorative ambient gradients */}
      <div className="absolute -top-32 -left-32 w-[520px] h-[520px] rounded-full bg-sky-900/20 blur-3xl pointer-events-none" />
      <div className="absolute -bottom-32 -right-32 w-[520px] h-[520px] rounded-full bg-purple-900/20 blur-3xl pointer-events-none" />
      <div className="absolute top-1/2 left-1/3 w-[420px] h-[420px] rounded-full bg-pink-900/15 blur-3xl pointer-events-none" />

      {/* Main Glassmorphic AI Workspace Card */}
      <div className="relative w-full max-w-[1560px] h-[98vh] max-h-[960px] rounded-[28px] sm:rounded-[32px] bg-[#11141c]/90 backdrop-blur-3xl border border-slate-800/80 shadow-[0_25px_80px_rgba(0,0,0,0.6)] flex overflow-hidden ring-1 ring-white/[0.06]">
        
        {/* Claude-Inspired Left Persistent Sidebar */}
        <ClaudeSidebar
          isOpen={sidebarOpen}
          onToggle={() => setSidebarOpen(!sidebarOpen)}
          activeView={activeView}
          onSelectView={setActiveView}
          sessions={sessions}
          activeSessionId={activeSessionId}
          onSelectSession={handleSelectSession}
          onNewChat={handleNewChat}
          onRenameSession={handleRenameSession}
          onDeleteSession={handleDeleteSession}
          onArchiveSession={handleArchiveSession}
        />

        {/* Dynamic Main Workspace Content */}
        <div className="flex-1 flex flex-col h-full min-w-0 relative overflow-hidden">
          
          {/* View: Chat Experience (Centered & Spacious) */}
          {activeView === 'chat' && (
            <ChatMainView
              messages={messages}
              activeSpec={activeSpec}
              onSendMessage={handleSendMessage}
              onApproveTest={handleApproveTest}
              onRejectTest={handleRejectTest}
              onSelectReportOption={(optId) => handleSendMessage(`Generate ${optId}`)}
              onOpenInventory={() => setInventoryOpen(true)}
              onOpenUpload={() => setUploadOpen(true)}
              onOpenReport={handleOpenReport}
              onResetSession={handleNewChat}
              backendOnline={backendOnline}
              isLoading={isLoading}
              onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
            />
          )}

          {/* View: Autonomous Cowork Workspace */}
          {activeView === 'cowork' && <CoworkWorkspace />}

          {/* View: Security Dashboard with Recharts */}
          {activeView === 'dashboard' && (
            <div className="h-full overflow-y-auto no-scrollbar p-4 sm:p-6">
              <SecurityDashboard
                onLoadFindingToWorkspace={(f) => {
                  setActiveView('findings');
                }}
                onOpenAssistant={() => setActiveView('chat')}
              />
            </div>
          )}

          {/* View: API Inventory */}
          {activeView === 'inventory' && (
            <div className="h-full overflow-y-auto no-scrollbar p-6 space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-slate-700/60">
                <div>
                  <h1 className="text-2xl font-bold text-slate-100 font-heading">
                    Parsed API Inventory & Risk Catalog
                  </h1>
                  <p className="text-xs text-slate-400 font-sans mt-0.5">
                    {activeSpec?.title} • {activeSpec?.endpoints.length || 0} endpoints parsed from specification
                  </p>
                </div>
                <button
                  onClick={() => setUploadOpen(true)}
                  className="px-4 py-2 rounded-full bg-[#1a1e29] hover:bg-[#21263a] text-slate-200 border border-slate-700/70 text-xs font-semibold flex items-center gap-2 shadow-xs transition-colors"
                >
                  <Plus className="w-3.5 h-3.5 text-pink-400" />
                  <span>Upload Specification</span>
                </button>
              </div>

              {/* Endpoints Table Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {activeSpec?.endpoints.map((ep) => (
                  <div
                    key={ep.id}
                    className="p-4 rounded-2xl bg-[#161a24]/80 border border-slate-700/60 shadow-xs space-y-2 hover:border-pink-500/40 transition-all"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 font-mono text-xs">
                        <span
                          className={`px-2 py-0.5 rounded-md font-bold text-[10px] ${
                            ep.method === 'GET'
                              ? 'bg-blue-900/50 text-blue-300'
                              : ep.method === 'POST'
                              ? 'bg-emerald-900/50 text-emerald-300'
                              : 'bg-amber-900/50 text-amber-300'
                          }`}
                        >
                          {ep.method}
                        </span>
                        <span className="font-semibold text-slate-200 truncate max-w-[220px]">
                          {ep.path}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800/80 text-slate-400">
                        {ep.authRequired ? 'Auth: Required' : 'Public'}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 font-sans">{ep.summary}</p>

                    <div className="flex items-center justify-between pt-2 border-t border-slate-700/40">
                      <span className="text-[10px] font-mono text-pink-400 bg-pink-900/30 px-2 py-0.5 rounded-full">
                        {ep.potentialRisks[0] || 'Authorization'}
                      </span>
                      <button
                        onClick={() => {
                          handleSendMessage(`Analyze security parameters for ${ep.method} ${ep.path}`);
                          setActiveView('chat');
                        }}
                        className="text-xs text-pink-400 hover:text-pink-300 font-medium"
                      >
                        Scan Vector →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* View: Security Findings & Analysis Workspace */}
          {activeView === 'findings' && (
            <div className="h-full overflow-y-auto no-scrollbar p-6">
              <AnalysisWorkspace
                onOpenAssistant={(context) => {
                  handleSendMessage(`Review analysis findings: ${context}`);
                  setActiveView('chat');
                }}
              />
            </div>
          )}

          {/* View: Assessment Reports */}
          {activeView === 'reports' && (
            <div className="h-full overflow-y-auto no-scrollbar p-6 space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-slate-700/60">
                <div>
                  <h1 className="text-2xl font-bold text-slate-100 font-heading">
                    Security Assessment Reports
                  </h1>
                  <p className="text-xs text-slate-400 font-sans mt-0.5">
                    Exportable audit reports with ML priority recommendations and defensive evidence.
                  </p>
                </div>
                <button
                  onClick={handleOpenReport}
                  className="px-4 py-2 rounded-full bg-gradient-to-r from-pink-500 to-rose-400 text-white text-xs font-semibold flex items-center gap-2 shadow-xs transition-all"
                >
                  <FileDown className="w-3.5 h-3.5" />
                  <span>Generate Active Report</span>
                </button>
              </div>

              <div className="p-8 rounded-2xl bg-[#161a24]/80 border border-slate-700/60 text-center space-y-3">
                <FileDown className="w-10 h-10 text-pink-500 mx-auto" />
                <h3 className="text-sm font-bold text-slate-100 font-heading">
                  Executive Defense Report Ready
                </h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Click the button below to view the comprehensive assessment report compiled from your active session.
                </p>
                <button
                  onClick={handleOpenReport}
                  className="px-5 py-2 rounded-full bg-[#1a1e29] text-slate-100 text-xs font-semibold hover:bg-[#21263a] border border-slate-700/70 transition-colors"
                >
                  Open Assessment Report Modal
                </button>
              </div>
            </div>
          )}

          {/* View: Settings Center */}
          {activeView === 'settings' && <SettingsCenter />}

        </div>

      </div>

      {/* Modals */}
      <EndpointInventoryModal
        isOpen={inventoryOpen}
        onClose={() => setInventoryOpen(false)}
        spec={activeSpec}
        onProposeEndpointTest={(ep) => {
          handleSendMessage(`Formulate targeted security probe for ${ep.method} ${ep.path}`);
          setActiveView('chat');
        }}
      />

      <SpecUploadModal
        isOpen={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onSpecLoaded={handleSpecLoaded}
      />

      <AssessmentReportModal
        isOpen={reportOpen}
        onClose={() => setReportOpen(false)}
        report={currentReport}
      />

    </div>
  );
}

export default App;
