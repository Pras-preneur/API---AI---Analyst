import React, { useRef, useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { IridescentOrb, OrbState } from './IridescentOrb';
import { ChatMessageItem } from './ChatMessageItem';
import { MessageComposer } from './MessageComposer';
import type { ApiSpec, ChatMessage } from '../../types/assistant';
import {
  FileCode,
  Plus,
  Layers,
  Menu,
  RotateCcw,
  Sparkles,
} from 'lucide-react';

interface ChatMainViewProps {
  messages: ChatMessage[];
  activeSpec: ApiSpec | null;
  onSendMessage: (text: string) => void;
  onApproveTest: (testId: string) => void;
  onRejectTest: (testId: string) => void;
  onSelectReportOption?: (optionId: string) => void;
  pendingTestIds?: Record<string, boolean>;
  onOpenInventory: () => void;
  onOpenUpload: () => void;
  onOpenReport: () => void;
  onResetSession?: () => void;
  backendOnline: boolean;
  isLoading: boolean;
  onToggleSidebar?: () => void;
}

export const ChatMainView: React.FC<ChatMainViewProps> = ({
  messages,
  activeSpec,
  onSendMessage,
  onApproveTest,
  onRejectTest,
  onSelectReportOption,
  onOpenInventory,
  onOpenUpload,
  onOpenReport,
  onResetSession,
  backendOnline,
  isLoading,
  onToggleSidebar,
}) => {
  const [isVoiceActive, setIsVoiceActive] = useState(false);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const prevMsgLength = useRef(0);

  const hasMessages = messages.length > 0;

  // Auto-scroll inside the conversation area ONLY (never touches window)
  useEffect(() => {
    if (hasMessages && scrollContainerRef.current) {
      const container = scrollContainerRef.current;
      container.scrollTo({
        top: container.scrollHeight,
        behavior: messages.length > prevMsgLength.current ? 'smooth' : 'auto',
      });
    }
    prevMsgLength.current = messages.length;
  }, [messages.length, isLoading, hasMessages]);

  const currentOrbState: OrbState = isLoading
    ? 'processing'
    : isVoiceActive
    ? 'listening'
    : 'idle';

  return (
    <div className="flex-1 flex flex-col h-full min-h-0 overflow-hidden bg-transparent font-sans">
      
      {/* 1. TOP HEADER BAR (Anchored across all views) */}
      <header className="h-13 sm:h-14 px-4 sm:px-6 flex items-center justify-between shrink-0 z-20 border-b border-slate-800/60 bg-[#13161e]/80 backdrop-blur-md">
        {/* Left: Mobile toggle + Active Spec pill */}
        <div className="flex items-center gap-2">
          {onToggleSidebar && (
            <button
              onClick={onToggleSidebar}
              className="p-1.5 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/70 lg:hidden transition-colors"
              title="Toggle Navigation Sidebar"
            >
              <Menu className="w-4 h-4" />
            </button>
          )}

          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#181c26] border border-slate-700/80 text-xs text-slate-200 shadow-xs">
            <FileCode className="w-3.5 h-3.5 text-pink-500 shrink-0" />
            <span className="font-semibold truncate max-w-[150px] sm:max-w-[280px]">
              {activeSpec ? activeSpec.title : 'No Specification Loaded'}
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-pink-900/50 text-pink-300 font-bold shrink-0">
              {activeSpec?.endpoints.length || 0} APIs
            </span>
          </div>

          <button
            onClick={onOpenInventory}
            className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-slate-400 hover:text-pink-400 hover:bg-slate-800/60 border border-slate-700/50 transition-colors"
            title="Inspect parsed endpoints and schemas"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Inventory</span>
          </button>
        </div>

        {/* Right: Backend Status & Actions */}
        <div className="flex items-center gap-2">
          <div
            title="FastAPI & Nemotron Backend Status"
            className="hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#13161e]/80 border border-slate-700/50 text-[11px] font-mono text-slate-400"
          >
            <span
              className={`w-2 h-2 rounded-full ${
                backendOnline ? 'bg-emerald-500' : 'bg-amber-400'
              } animate-pulse`}
            />
            <span>{backendOnline ? 'SLM Online' : 'Local Engine'}</span>
          </div>

          {hasMessages && onResetSession && (
            <button
              onClick={onResetSession}
              className="px-3 py-1 rounded-full bg-pink-900/40 hover:bg-pink-900/60 text-pink-300 border border-pink-800/50 text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors"
              title="Start a fresh chat with the 3D Intelligence Orb"
            >
              <RotateCcw className="w-3 h-3" />
              <span>New Chat</span>
            </button>
          )}

          <button
            onClick={onOpenUpload}
            className="px-3 py-1 rounded-full bg-[#1a1e29] hover:bg-[#21263a] text-slate-200 border border-slate-700/70 text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-all hover:border-pink-500/40 active:scale-95"
            title="Connect or Upload OpenAPI Specification"
          >
            <Plus className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Connect Spec</span>
          </button>
        </div>
      </header>

      {/* 2. DYNAMIC WORKSPACE (Smooth AnimatePresence transition between Welcome and Expanded Chat) */}
      <div className="flex-1 min-h-0 relative overflow-hidden flex flex-col">
        <AnimatePresence mode="wait">
          
          {/* STATE A: INITIAL WELCOME STATE (Orb centerpiece, heading, chips, composer) */}
          {!hasMessages ? (
            <motion.div
              key="welcome-state"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.92, y: -28, transition: { duration: 0.32, ease: [0.16, 1, 0.3, 1] } }}
              transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
              className="flex-1 min-h-0 flex flex-col items-center justify-between px-4 sm:px-6 py-4 overflow-hidden w-full max-w-4xl mx-auto"
            >
              {/* Centered Heading */}
              <div className="text-center space-y-2 select-none pt-2 sm:pt-4">
                <h1 className="text-3xl sm:text-4xl md:text-[2.6rem] font-extrabold tracking-tight text-slate-100 font-heading leading-tight">
                  <span className="text-[#f472b6] font-semibold">AI Powers </span>
                  <span className="text-slate-100 font-bold">API Security </span>
                  <span className="text-[#c084fc] font-semibold">And </span>
                  <br className="hidden sm:inline" />
                  <span className="text-slate-100 font-bold">Voice Access</span>
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 font-sans max-w-lg mx-auto leading-relaxed">
                  Autonomous API vulnerability intelligence, automated BOLA/IDOR probes, and human-in-the-loop verification.
                </p>
              </div>

              {/* Central 3D Animated Pink Orb */}
              <div className="my-auto py-2 flex flex-col items-center">
                <IridescentOrb
                  size={200}
                  state={currentOrbState}
                  onClick={() => setIsVoiceActive((prev) => !prev)}
                />
              </div>

              {/* Bottom Centered Composer & Quick Actions */}
              <div className="w-full max-w-3xl shrink-0 pb-2">
                <MessageComposer
                  onSendMessage={onSendMessage}
                  onOpenUpload={onOpenUpload}
                  onOpenInventory={onOpenInventory}
                  onOpenReport={onOpenReport}
                  onVoiceStateChange={setIsVoiceActive}
                  isLoading={isLoading}
                  showChips={true}
                />
              </div>
            </motion.div>
          ) : (

            /* STATE B: EXPANDED FULL-SIZE CONVERSATION WORKSPACE */
            <motion.div
              key="chat-workspace"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20, transition: { duration: 0.25 } }}
              transition={{ duration: 0.38, ease: [0.16, 1, 0.3, 1] }}
              className="flex-1 min-h-0 flex flex-col overflow-hidden w-full"
            >
              {/* Scrollable Conversation Stream — Wide, Comfortable, Professional AI Layout */}
              <div
                ref={scrollContainerRef}
                className="flex-1 min-h-0 overflow-y-auto no-scrollbar"
              >
                <div className="max-w-4xl lg:max-w-5xl w-full mx-auto px-4 sm:px-6 md:px-8 py-6 space-y-4">
                  {messages.map((msg) => (
                    <ChatMessageItem
                      key={msg.id}
                      message={msg}
                      onApproveTest={onApproveTest}
                      onRejectTest={onRejectTest}
                      onSelectReportOption={onSelectReportOption}
                    />
                  ))}

                  {/* Real-time processing indicator */}
                  {isLoading && (
                    <div className="py-2 px-4 flex justify-start animate-in fade-in duration-200">
                      <div className="flex items-center gap-2.5 bg-[#161a24]/95 border border-pink-800/50 rounded-full px-4 py-2 shadow-xs text-xs text-pink-300 font-mono">
                        <span className="w-2.5 h-2.5 rounded-full bg-pink-500 animate-ping" />
                        <span>Evaluating vectors with SLM reasoning & ML Priority model...</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Persistent Bottom Composer — Anchored at bottom, NEVER overlaps messages */}
              <footer className="shrink-0 w-full px-4 sm:px-6 md:px-8 py-3 bg-[#13161e]/85 backdrop-blur-xl border-t border-slate-800/60 z-20">
                <div className="max-w-4xl lg:max-w-5xl w-full mx-auto">
                  <MessageComposer
                    onSendMessage={onSendMessage}
                    onOpenUpload={onOpenUpload}
                    onOpenInventory={onOpenInventory}
                    onOpenReport={onOpenReport}
                    onVoiceStateChange={setIsVoiceActive}
                    isLoading={isLoading}
                    showChips={true}
                  />
                </div>
              </footer>
            </motion.div>
          )}

        </AnimatePresence>
      </div>

    </div>
  );
};