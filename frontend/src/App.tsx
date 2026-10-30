import { ExecutionConfigModal } from './components/chat/ExecutionConfigModal';
import { FindingsModal } from './components/chat/FindingsModal';
import type {
  BackendExecutionConfig,
  BackendFindingReviewRequest,
  BackendFinding,
  BackendReport,
} from './types/backend';
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
  fetchBackendProposals,
  generateAssessmentReport,
} from './services/chatService';
import { checkBackendHealth, approveProposal, rejectProposal, executeTests, reviewFinding, createReport } from './services/api';
import { Layers, ShieldAlert, FileDown, Plus, FileCode, CheckCircle2 } from 'lucide-react';

const INITIAL_GREETING: ChatMessage = {
  id: 'm-initial',
  sender: 'assistant',
  text:
    `Welcome to the **API Intelligence & Security Testing Assistant**.\n\n` +
    `I am your conversational, human-in-the-loop security testing copilot. Connect or upload an OpenAPI specification ` +
    `to initialize a verified backend testing session, inspect parsed endpoints, and formulate security test proposals.`,
  timestamp: 'Just now',
};

const DEFAULT_SESSIONS: ChatSession[] = [
  {
    id: 'session-default-1',
    title: 'API Security Audit Session',
    createdAt: Date.now() - 3600000,
    updatedAt: Date.now() - 1800000,
    messages: [INITIAL_GREETING],
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

  // Specifications & Backend Session
  const [specs, setSpecs] = useState<ApiSpec[]>(SAMPLE_SPECS);
  const [activeSpec, setActiveSpec] = useState<ApiSpec | null>(null);
  const [backendSessionId, setBackendSessionId] = useState<string | null>(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [isGeneratingProposals, setIsGeneratingProposals] = useState(false);
  const [pendingProposalActions, setPendingProposalActions] = useState<Record<string, boolean>>({});

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
  const [executionModalOpen, setExecutionModalOpen] = useState(false);
  const [findingsModalOpen, setFindingsModalOpen] = useState(false);
  const [sessionFindings, setSessionFindings] = useState<BackendFinding[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [isReviewingFinding, setIsReviewingFinding] = useState(false);

  // Save sessions to localStorage
  useEffect(() => {
    try {
      const sanitizedSessions = sessions.map((ses) => ({
        id: ses.id,
        title: ses.title,
        createdAt: ses.createdAt,
        updatedAt: ses.updatedAt,
        messages: ses.messages,
        specId: ses.specId,
        isArchived: ses.isArchived,
      }));
      localStorage.setItem('zynora_chat_sessions_v4', JSON.stringify(sanitizedSessions));
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
    setSpecs((prev) => [newSpec, ...prev.filter((sp) => sp.id !== newSpec.id)]);
    setActiveSpec(newSpec);
    if (newSpec.sessionId) {
      setBackendSessionId(newSpec.sessionId);
    }

    const switchMsg: ChatMessage = {
      id: `m-${Date.now()}`,
      sender: 'assistant',
      text:
        `### OpenAPI Specification Ingested\n\n` +
        `Successfully parsed **${newSpec.title}** (v${newSpec.version}) with **${newSpec.endpoints.length} endpoints**.\n` +
        `**Active Backend Session ID:** \`${newSpec.sessionId || 'Pending'}\`\n\n` +
        `The endpoint inventory has been cataloged in the backend session store. Type **"propose tests"** or inspect the **Inventory** to view endpoints.`,
      timestamp: 'Just now',
      specContext: {
        specTitle: newSpec.title,
        endpointCount: newSpec.endpoints.length,
      },
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

    const activeSessionData = sessions.find((ses) => ses.id === targetSessionId);
    const baseMessages = activeSessionData ? activeSessionData.messages : messages;
    const updated = [...baseMessages, userMsg];

    setMessages(updated);
    setSessions((prev) =>
      prev.map((ses) =>
        ses.id === targetSessionId
          ? {
              ...ses,
              title: ses.messages.length === 0 ? (text.slice(0, 26) + (text.length > 26 ? '...' : '')) : ses.title,
              messages: updated,
              updatedAt: Date.now(),
            }
          : ses
      )
    );

    setIsLoading(true);

    const p = text.toLowerCase();
    const isProposalIntent =
      p.includes('propose') ||
      p.includes('test') ||
      p.includes('scan') ||
      p.includes('audit') ||
      p.includes('bola') ||
      p.includes('bfla');

    if (isProposalIntent) {
      if (!backendSessionId || !activeSpec) {
        const assistantMsg: ChatMessage = {
          id: `m-${Date.now() + 1}`,
          sender: 'assistant',
          text:
            `### No Active Assessment Session\n\n` +
            `To formulate verified security test proposals, please connect or upload an OpenAPI specification first.\n` +
            `Click **Connect Spec** in the top header or load an evaluator sample to create a backend session.`,
          timestamp: 'Just now',
        };
        const finalMessages = [...updated, assistantMsg];
        updateCurrentSessionMessages(finalMessages, targetSessionId);
        setIsLoading(false);
        return;
      }

      if (isGeneratingProposals) {
        setIsLoading(false);
        return;
      }

      setIsGeneratingProposals(true);
      try {
        const proposals = await fetchBackendProposals(backendSessionId, true);
        const assistantMsg: ChatMessage = {
          id: `m-${Date.now() + 1}`,
          sender: 'assistant',
          text:
            proposals.length > 0
              ? `### Security Test Proposals Formulated (${proposals.length})\n\n` +
                `Formulated ${proposals.length} security test proposals for **${activeSpec.title}** via backend session \`${backendSessionId}\`.\n` +
                `Each proposal requires your explicit operator approval before execution.\n\n` +
                `Review the proposed test cards below, inspect the payload assertion previews, and click **Approve** or **Reject**:`
              : `### No Security Proposals Generated\n\n` +
                `The backend analyzed **${activeSpec.endpoints.length} endpoints** in session \`${backendSessionId}\`, ` +
                `but no endpoints matched target authorization vectors (BOLA, BFLA, or Broken Authentication).`,
          timestamp: 'Just now',
          proposedTests: proposals.length > 0 ? proposals : undefined,
        };
        const finalMessages = [...updated, assistantMsg];
        updateCurrentSessionMessages(finalMessages, targetSessionId);
      } catch (err: any) {
        const errorMsg: ChatMessage = {
          id: `m-${Date.now() + 1}`,
          sender: 'assistant',
          text: `### Proposal Generation Failed\n\nBackend error: ${err.details || err.message || 'Unable to fetch proposals from backend.'}`,
          timestamp: 'Just now',
        };
        const finalMessages = [...updated, errorMsg];
        updateCurrentSessionMessages(finalMessages, targetSessionId);
      } finally {
        setIsGeneratingProposals(false);
        setIsLoading(false);
      }
      return;
    }

    try {
      const slmResult = await sendChatMessageToSLM(text, {
        specTitle: activeSpec?.title,
        endpointCount: activeSpec?.endpoints.length,
      });

      const assistantMsg: ChatMessage = {
        id: `m-${Date.now() + 1}`,
        sender: 'assistant',
        text: typeof slmResult === 'string' ? slmResult : slmResult.reply,
        timestamp: 'Just now',
        reportOptions: typeof slmResult === 'object' ? slmResult.reportOptions : undefined,
      };

      const finalMessages = [...updated, assistantMsg];
      updateCurrentSessionMessages(finalMessages, targetSessionId);
    } catch {
      const errorMsg: ChatMessage = {
        id: `m-${Date.now() + 1}`,
        sender: 'assistant',
        text: 'Local SLM engine offline or initializing. Please ensure the backend is connected.',
        timestamp: 'Just now',
      };
      const finalMessages = [...updated, errorMsg];
      updateCurrentSessionMessages(finalMessages, targetSessionId);
    } finally {
      setIsLoading(false);
    }
  };

  // Approve test (Phase 2: Transition to APPROVED via backend without execution)
  const handleApproveTest = async (testId: string) => {
    if (!backendSessionId) {
      alert('No active backend assessment session. Please upload a specification first.');
      return;
    }
    if (pendingProposalActions[testId]) return;

    setPendingProposalActions((prev) => ({ ...prev, [testId]: true }));

    try {
      const updatedBackendTest = await approveProposal(backendSessionId, testId);

      const updatedMessages = messages.map((msg) => {
        if (!msg.proposedTests) return msg;
        return {
          ...msg,
          proposedTests: msg.proposedTests.map((t) =>
            t.testId === testId
              ? {
                  ...t,
                  status: 'approved' as const,
                  approvedAt: updatedBackendTest.approved_at,
                }
              : t
          ),
        };
      });

      updateCurrentSessionMessages(updatedMessages);
    } catch (err: any) {
      alert(`Backend rejected proposal approval: ${err.details || err.message}`);
    } finally {
      setPendingProposalActions((prev) => ({ ...prev, [testId]: false }));
    }
  };

  // Phase 3B: Controlled Execution of Approved Proposals
  const handleExecuteApprovedTests = async (
    selectedProposalIds: string[],
    config: BackendExecutionConfig
  ) => {
    if (!backendSessionId) {
      alert('No active backend assessment session. Please upload a specification first.');
      return;
    }
    setIsExecuting(true);
    try {
      const returnedFindings = await executeTests(backendSessionId, {
        proposal_ids: selectedProposalIds,
        target: config.target_base_url,
        config,
      });

      // Update session findings
      setSessionFindings((prev) => {
        const existingIds = new Set(prev.map((f) => f.finding_id));
        const filtered = prev.filter((f) => !returnedFindings.some((rf) => rf.finding_id === f.finding_id));
        return [...filtered, ...returnedFindings];
      });

      // Mark executed proposals in messages as completed
      const updatedMessages = messages.map((msg) => {
        if (!msg.proposedTests) return msg;
        return {
          ...msg,
          proposedTests: msg.proposedTests.map((t) =>
            selectedProposalIds.includes(t.testId)
              ? {
                  ...t,
                  status: 'completed' as const,
                  executionEvidence: {
                    httpStatus: 200,
                    responseSnippet: 'Probed by SPEC_DRIVEN engine',
                    findingConfirmed: false,
                    timestamp: new Date().toISOString(),
                  },
                }
              : t
          ),
        };
      });

      // Append assistant execution completion message
      const execMsg: ChatMessage = {
        id: `m-exec-${Date.now()}`,
        sender: 'assistant',
        text:
          `### 🎯 Controlled Security Execution Completed\n\n` +
          `Target: \`${config.target_base_url}\` • Mode: \`${config.mode}\`\n\n` +
          `Successfully executed **${selectedProposalIds.length}** approved security probe(s). ` +
          `The backend differential engine returned **${returnedFindings.length}** finding(s) with sanitized evidence.\n\n` +
          `> [!NOTE]\n` +
          `> **Vulnerability Confirmation Invariant:** Probing outcomes such as \`SUSPECTED\` or HTTP status \`200 OK\` do **not** confirm a vulnerability. ` +
          `Inspect the sanitized evidence below and submit an explicit human auditor review decision.`,
        timestamp: 'Just now',
        backendFindings: returnedFindings,
      };

      updateCurrentSessionMessages([...updatedMessages, execMsg]);
    } catch (err: any) {
      alert(`Backend execution error: ${err?.details || err?.message}`);
      throw err;
    } finally {
      setIsExecuting(false);
    }
  };

  // Phase 3B: Explicit Human Review of Findings
  const handleReviewFinding = async (
    findingId: string,
    review: BackendFindingReviewRequest
  ) => {
    if (!backendSessionId) {
      alert('No active backend assessment session. Please upload a specification first.');
      return;
    }
    setIsReviewingFinding(true);
    try {
      const updatedFinding = await reviewFinding(backendSessionId, findingId, review);

      // Update session findings list
      setSessionFindings((prev) =>
        prev.map((f) => (f.finding_id === findingId ? updatedFinding : f))
      );

      // Update finding inside chat messages
      const updatedMessages = messages.map((msg) => {
        if (!msg.backendFindings) return msg;
        return {
          ...msg,
          backendFindings: msg.backendFindings.map((f) =>
            f.finding_id === findingId ? updatedFinding : f
          ),
        };
      });
      updateCurrentSessionMessages(updatedMessages);
    } catch (err: any) {
      alert(`Human review rejected by backend: ${err?.details || err?.message}`);
      throw err;
    } finally {
      setIsReviewingFinding(false);
    }
  };

  // Reject test (Phase 2: Transition to REJECTED via backend)
  const handleRejectTest = async (testId: string) => {
    if (!backendSessionId) {
      alert('No active backend assessment session. Please upload a specification first.');
      return;
    }
    if (pendingProposalActions[testId]) return;

    setPendingProposalActions((prev) => ({ ...prev, [testId]: true }));

    try {
      const updatedBackendTest = await rejectProposal(backendSessionId, testId);

      const updatedMessages = messages.map((msg) => {
        if (!msg.proposedTests) return msg;
        return {
          ...msg,
          proposedTests: msg.proposedTests.map((t) =>
            t.testId === testId
              ? {
                  ...t,
                  status: 'rejected' as const,
                  rejectedAt: updatedBackendTest.rejected_at,
                }
              : t
          ),
        };
      });

      updateCurrentSessionMessages(updatedMessages);
    } catch (err: any) {
      alert(`Backend rejected proposal rejection: ${err.details || err.message}`);
    } finally {
      setPendingProposalActions((prev) => ({ ...prev, [testId]: false }));
    }
  };

  // Open Report Modal
  const handleOpenReport = async () => {
    if (!activeSpec) return;
    const allTests: ProposedTest[] = [];
    const allFindings: SecurityFindingReportItem[] = [];

    messages.forEach((m) => {
      if (m.proposedTests) allTests.push(...m.proposedTests);
      if (m.findings) allFindings.push(...m.findings);
    });

    let backendReport: BackendReport | undefined = undefined;
    if (backendSessionId) {
      try {
        backendReport = await createReport(backendSessionId, 'http://127.0.0.1:8001');
      } catch (err) {
        console.warn('Backend report generation failed, falling back to local session data:', err);
      }
    }

    const report = generateAssessmentReport(
      activeSpec,
      allTests,
      allFindings,
      backendReport,
      backendSessionId || undefined
    );
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
              onReviewFinding={handleReviewFinding}
              onOpenExecutionModal={() => setExecutionModalOpen(true)}
              onOpenFindings={() => setFindingsModalOpen(true)}
              findingsCount={sessionFindings.length}
              approvedProposalsCount={
                messages.flatMap((m) => m.proposedTests || []).filter((t) => t.status === 'approved').length
              }
              onOpenInventory={() => setInventoryOpen(true)}
              onOpenUpload={() => setUploadOpen(true)}
              onOpenReport={handleOpenReport}
              onResetSession={handleNewChat}
              backendOnline={backendOnline}
              isLoading={isLoading}
              pendingTestIds={pendingProposalActions}
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

      <ExecutionConfigModal
        isOpen={executionModalOpen}
        onClose={() => setExecutionModalOpen(false)}
        proposals={messages.flatMap((m) => m.proposedTests || [])}
        onExecute={handleExecuteApprovedTests}
        isExecuting={isExecuting}
      />

      <FindingsModal
        isOpen={findingsModalOpen}
        onClose={() => setFindingsModalOpen(false)}
        findings={sessionFindings}
        onReviewFinding={handleReviewFinding}
        isReviewing={isReviewingFinding}
      />

    </div>
  );
}

export default App;
