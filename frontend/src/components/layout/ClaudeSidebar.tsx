import React, { useState } from 'react';
import {
  Plus,
  MessageSquare,
  Sparkles,
  Layers,
  ShieldAlert,
  FileDown,
  Settings,
  Search,
  MoreHorizontal,
  Edit2,
  Trash2,
  Archive,
  ChevronLeft,
  ChevronRight,
  Shield,
  Clock,
  User,
} from 'lucide-react';
import type { WorkspaceView, ChatSession } from '../../types/workspace';

interface ClaudeSidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  activeView: WorkspaceView;
  onSelectView: (view: WorkspaceView) => void;
  sessions: ChatSession[];
  activeSessionId: string;
  onSelectSession: (sessionId: string) => void;
  onNewChat: () => void;
  onRenameSession: (sessionId: string, newTitle: string) => void;
  onDeleteSession: (sessionId: string) => void;
  onArchiveSession: (sessionId: string) => void;
}

export const ClaudeSidebar: React.FC<ClaudeSidebarProps> = ({
  isOpen,
  onToggle,
  activeView,
  onSelectView,
  sessions,
  activeSessionId,
  onSelectSession,
  onNewChat,
  onRenameSession,
  onDeleteSession,
  onArchiveSession,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [editingSessionId, setEditingSessionId] = useState<string | null>(null);
  const [editingTitle, setEditingTitle] = useState('');
  const [menuOpenSessionId, setMenuOpenSessionId] = useState<string | null>(null);

  const filteredSessions = sessions.filter(
    (s) =>
      !s.isArchived &&
      (s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.messages.some((m) => m.text.toLowerCase().includes(searchQuery.toLowerCase())))
  );

  const startRename = (s: ChatSession) => {
    setEditingSessionId(s.id);
    setEditingTitle(s.title);
    setMenuOpenSessionId(null);
  };

  const handleRenameSubmit = (id: string) => {
    if (editingTitle.trim()) {
      onRenameSession(id, editingTitle.trim());
    }
    setEditingSessionId(null);
  };

  return (
    <aside
      className={`fixed lg:static top-0 bottom-0 left-0 z-40 transition-all duration-300 ease-in-out flex flex-col bg-[#0d1017]/95 backdrop-blur-2xl border-r border-slate-800/70 select-none ${
        isOpen ? 'w-64 sm:w-72' : 'w-0 lg:w-16'
      } overflow-hidden shadow-xs shrink-0`}
    >
      {/* Top Brand Header */}
      <div className="h-16 px-4 flex items-center justify-between border-b border-slate-800/60 shrink-0">
        <div className={`flex items-center gap-2.5 ${!isOpen && 'lg:hidden'}`}>
          <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-pink-500/30 via-purple-500/25 to-cyan-500/25 border border-slate-700/60 shadow-xs flex items-center justify-center">
            <span className="text-xs font-black bg-gradient-to-r from-pink-500 to-purple-600 bg-clip-text text-transparent font-heading">
              Z
            </span>
          </div>
          <div className="leading-tight">
            <div className="font-extrabold text-xs tracking-wide text-slate-100 font-heading">
              ZYNORA <span className="text-pink-600">AI</span>
            </div>
            <div className="text-[10px] font-mono text-slate-500">Security Workspace</div>
          </div>
        </div>

        <button
          onClick={onToggle}
          className="p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-800/70 transition-colors ml-auto"
          title={isOpen ? 'Collapse Sidebar' : 'Expand Sidebar'}
        >
          {isOpen ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>
      </div>

      {/* Primary Action: + New Chat */}
      <div className="p-3 shrink-0">
        <button
          onClick={onNewChat}
          className={`w-full py-2.5 px-3 rounded-2xl bg-gradient-to-r from-pink-500 via-rose-500 to-pink-500 hover:opacity-95 text-white text-xs font-semibold flex items-center justify-center gap-2 transition-all shadow-md shadow-pink-500/20 active:scale-95 group ${
            !isOpen && 'lg:px-0 lg:py-2.5'
          }`}
          title="Start Fresh Security Chat Session"
        >
          <Plus className="w-4 h-4 group-hover:scale-110 transition-transform shrink-0" />
          <span className={!isOpen ? 'lg:hidden' : ''}>New Chat</span>
        </button>
      </div>

      {/* Workspace Navigation Views */}
      <div className="px-3 py-1 space-y-1 shrink-0">
        {[
          { id: 'chat', label: 'Security Chat', icon: MessageSquare },
          { id: 'cowork', label: 'Cowork Tasks', icon: Sparkles, badge: 'Auto' },
          { id: 'dashboard', label: 'Security Dashboard', icon: Shield },
          { id: 'inventory', label: 'API Inventory', icon: Layers },
          { id: 'findings', label: 'Security Findings', icon: ShieldAlert },
          { id: 'reports', label: 'Assessment Reports', icon: FileDown },
        ].map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectView(item.id as WorkspaceView)}
              className={`w-full py-2 px-3 rounded-xl text-xs font-medium flex items-center justify-between transition-all group ${
                isActive
                  ? 'bg-[#1c2230] text-pink-400 font-semibold border border-slate-700/60 shadow-xs'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
              } ${!isOpen && 'lg:px-0 lg:justify-center'}`}
              title={item.label}
            >
              <div className="flex items-center gap-2.5 truncate">
                <Icon
                  className={`w-4 h-4 shrink-0 transition-colors ${
                    isActive ? 'text-pink-400' : 'text-slate-500 group-hover:text-slate-300'
                  }`}
                />
                <span className={`truncate ${!isOpen && 'lg:hidden'}`}>{item.label}</span>
              </div>
              {item.badge && isOpen && (
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-pink-900/40 text-pink-300 font-bold uppercase">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Search Bar for Chat History */}
      {isOpen && (
        <div className="px-3 pt-3 pb-1 shrink-0">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search chat history..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-slate-800/50 border border-slate-700/60 rounded-xl text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-pink-500/40"
            />
          </div>
        </div>
      )}

      {/* Chat History List (Organized by sessions) */}
      <div className={`flex-1 overflow-y-auto px-3 py-2 space-y-1 no-scrollbar ${!isOpen && 'lg:hidden'}`}>
        <div className="text-[10px] font-mono uppercase tracking-wider text-slate-600 px-2 py-1 font-semibold flex items-center justify-between">
          <span>Previous Sessions ({filteredSessions.length})</span>
          <Clock className="w-3 h-3 text-slate-600" />
        </div>

        {filteredSessions.length === 0 ? (
          <div className="text-center py-6 text-xs text-slate-500">
            No matching sessions
          </div>
        ) : (
          filteredSessions.map((session) => {
            const isSelected = activeSessionId === session.id && activeView === 'chat';
            const isEditing = editingSessionId === session.id;

            return (
              <div
                key={session.id}
                className={`group relative rounded-xl px-2.5 py-2 text-xs transition-all flex items-center justify-between ${
                  isSelected
                    ? 'bg-[#1c2230] text-slate-100 font-semibold shadow-xs'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                }`}
              >
                {isEditing ? (
                  <input
                    type="text"
                    value={editingTitle}
                    onChange={(e) => setEditingTitle(e.target.value)}
                    onBlur={() => handleRenameSubmit(session.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') handleRenameSubmit(session.id);
                      if (e.key === 'Escape') setEditingSessionId(null);
                    }}
                    autoFocus
                    className="w-full px-2 py-0.5 text-xs bg-[#0d1017]/90 border border-pink-500/50 rounded font-normal text-slate-100"
                  />
                ) : (
                  <button
                    onClick={() => {
                      onSelectSession(session.id);
                      onSelectView('chat');
                    }}
                    className="flex-1 text-left truncate flex items-center gap-2"
                  >
                    <MessageSquare className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                    <span className="truncate">{session.title}</span>
                  </button>
                )}

                {/* Session Actions Menu Trigger */}
                <div className="relative">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setMenuOpenSessionId(
                        menuOpenSessionId === session.id ? null : session.id
                      );
                    }}
                    className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-700/70 text-slate-500 hover:text-slate-200 transition-opacity"
                    title="Session Options"
                  >
                    <MoreHorizontal className="w-3.5 h-3.5" />
                  </button>

                  {/* Context Popup */}
                  {menuOpenSessionId === session.id && (
                    <div className="absolute right-0 top-6 w-36 bg-[#13161e] border border-slate-700/70 rounded-xl shadow-lg p-1 z-50 text-[11px] space-y-0.5">
                      <button
                        onClick={() => startRename(session)}
                        className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800/70 flex items-center gap-1.5 text-slate-300"
                      >
                        <Edit2 className="w-3 h-3 text-slate-600" />
                        <span>Rename</span>
                      </button>
                      <button
                        onClick={() => {
                          onArchiveSession(session.id);
                          setMenuOpenSessionId(null);
                        }}
                        className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800/70 flex items-center gap-1.5 text-slate-300"
                      >
                        <Archive className="w-3 h-3 text-slate-600" />
                        <span>Archive</span>
                      </button>
                      <button
                        onClick={() => {
                          onDeleteSession(session.id);
                          setMenuOpenSessionId(null);
                        }}
                        className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-rose-900/30 flex items-center gap-1.5 text-rose-400"
                      >
                        <Trash2 className="w-3 h-3 text-rose-400" />
                        <span>Delete</span>
                      </button>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Bottom Footer: Settings & Profile */}
      <div className="p-3 border-t border-slate-800/60 shrink-0 space-y-1">
        <button
          onClick={() => onSelectView('settings')}
          className={`w-full py-2 px-3 rounded-xl text-xs font-medium flex items-center gap-2.5 transition-all ${
            activeView === 'settings'
              ? 'bg-[#1c2230] text-slate-100 font-semibold'
              : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
          } ${!isOpen && 'lg:px-0 lg:justify-center'}`}
          title="Settings & AI Configuration"
        >
          <Settings className="w-4 h-4 text-slate-500 shrink-0" />
          <span className={`truncate ${!isOpen && 'lg:hidden'}`}>Settings</span>
        </button>

        {/* User Card */}
        {isOpen && (
          <div className="pt-2 px-2 flex items-center gap-2.5 text-slate-200">
            <div className="w-7 h-7 rounded-full bg-pink-900/50 border border-pink-700/50 flex items-center justify-center text-pink-300 text-xs font-bold">
              SL
            </div>
            <div className="leading-tight truncate">
              <div className="font-semibold text-xs truncate text-slate-200">Security Lead</div>
              <div className="text-[10px] text-slate-500 font-mono">Enterprise Node</div>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
