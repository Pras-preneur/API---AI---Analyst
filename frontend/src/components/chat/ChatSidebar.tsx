import React from 'react';
import {
  Plus,
  FileCode,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Shield,
  Sparkles,
  Database,
  Upload,
} from 'lucide-react';
import type { ApiSpec } from '../../types/assistant';
import { SAMPLE_SPECS } from '../../data/sampleSpecs';

interface ChatSidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  activeSpec: ApiSpec | null;
  specs: ApiSpec[];
  onSelectSpec: (spec: ApiSpec) => void;
  onOpenUpload: () => void;
  onNewSession: () => void;
}

export const ChatSidebar: React.FC<ChatSidebarProps> = ({
  isOpen,
  onToggle,
  activeSpec,
  specs,
  onSelectSpec,
  onOpenUpload,
  onNewSession,
}) => {
  return (
    <aside
      className={`fixed lg:static top-0 bottom-0 left-0 z-40 transition-all duration-300 ease-in-out flex flex-col bg-slate-50/95 border-r border-slate-200/80 ${
        isOpen ? 'w-72' : 'w-0 lg:w-16'
      } overflow-hidden select-none shadow-[1px_0_3px_rgba(0,0,0,0.02)]`}
    >
      {/* Top Header / Brand */}
      <div className="h-16 px-4 flex items-center justify-between border-b border-slate-200/80 shrink-0">
        <div className={`flex items-center gap-2.5 ${!isOpen && 'lg:hidden'}`}>
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-sky-400/20 to-blue-500/20 border border-sky-300/80 flex items-center justify-center shadow-xs">
            <Shield className="w-4 h-4 text-sky-600" />
          </div>
          <div className="leading-tight">
            <div className="font-extrabold text-sm tracking-wide text-slate-800 font-display">
              API TESTER <span className="text-sky-600 font-bold">AI</span>
            </div>
            <div className="text-[10px] font-mono text-slate-500">Human-in-the-Loop</div>
          </div>
        </div>

        <button
          onClick={onToggle}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition-colors ml-auto"
          title={isOpen ? 'Collapse Sidebar' : 'Expand Sidebar'}
        >
          {isOpen ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>
      </div>

      {/* Primary Action: New Assessment */}
      <div className="p-3 shrink-0">
        <button
          onClick={onNewSession}
          className={`w-full py-2.5 px-3 rounded-xl bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-semibold flex items-center justify-center gap-2 transition-all shadow-sm group hover:border-sky-300 ${
            !isOpen && 'lg:px-0'
          }`}
          title="Start New Assessment Session"
        >
          <Plus className="w-4 h-4 text-sky-500 group-hover:scale-110 transition-transform shrink-0" />
          <span className={!isOpen ? 'lg:hidden' : ''}>New Assessment</span>
        </button>
      </div>

      {/* Specifications List */}
      <div className={`flex-1 overflow-y-auto px-3 py-2 space-y-4 ${!isOpen && 'lg:hidden'}`}>
        
        {/* Active Specifications */}
        <div>
          <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-500 px-2 mb-1.5">
            <span>API Specifications</span>
            <button
              onClick={onOpenUpload}
              className="hover:text-sky-600 text-slate-500 flex items-center gap-1 font-semibold transition-colors"
              title="Upload OpenAPI Specification"
            >
              <Upload className="w-3 h-3" />
              <span>Upload</span>
            </button>
          </div>

          <div className="space-y-1">
            {specs.map((spec) => {
              const isActive = activeSpec?.id === spec.id;
              return (
                <button
                  key={spec.id}
                  onClick={() => onSelectSpec(spec)}
                  className={`w-full text-left px-3 py-2.5 rounded-xl text-xs transition-all flex items-start gap-2.5 ${
                    isActive
                      ? 'bg-sky-50 border border-sky-200/90 text-sky-950 font-medium shadow-xs'
                      : 'hover:bg-slate-100/80 text-slate-600 border border-transparent'
                  }`}
                >
                  <FileCode className={`w-4 h-4 mt-0.5 shrink-0 ${isActive ? 'text-sky-600' : 'text-slate-400'}`} />
                  <div className="truncate flex-1">
                    <div className="truncate font-medium">{spec.title}</div>
                    <div className="text-[10px] font-mono text-slate-500 mt-0.5 flex items-center gap-1.5">
                      <span>v{spec.version}</span>
                      <span>•</span>
                      <span className="text-sky-600 font-semibold">{spec.endpoints.length} endpoints</span>
                    </div>
                  </div>
                  {isActive && <CheckCircle2 className="w-3.5 h-3.5 text-sky-600 mt-0.5 shrink-0" />}
                </button>
              );
            })}
          </div>
        </div>

        {/* Demo Specs Quick Loaders */}
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-2 mb-1.5">
            Quick-Load Sample Specs
          </div>

          <div className="space-y-1">
            {SAMPLE_SPECS.map((sample) => (
              <button
                key={sample.id}
                onClick={() => onSelectSpec(sample)}
                className="w-full text-left px-3 py-2 rounded-xl text-xs hover:bg-slate-100 text-slate-600 hover:text-slate-900 transition-colors flex items-center gap-2 group border border-transparent hover:border-slate-200/60"
              >
                <Database className="w-3.5 h-3.5 text-slate-400 group-hover:text-sky-600 transition-colors shrink-0" />
                <span className="truncate">{sample.title.split(' ')[0]} API</span>
                <span className="text-[10px] font-mono text-slate-400 ml-auto shrink-0">v{sample.version}</span>
              </button>
            ))}
          </div>
        </div>

      </div>

      {/* Bottom Footer Telemetry */}
      <div className={`p-3 border-t border-slate-200/80 shrink-0 ${!isOpen && 'lg:hidden'}`}>
        <div className="p-2.5 rounded-xl bg-white border border-slate-200 text-[11px] font-mono text-slate-600 space-y-1 shadow-xs">
          <div className="flex items-center gap-1.5 text-sky-700 font-semibold">
            <Sparkles className="w-3.5 h-3.5 text-sky-500" />
            <span>Zynora-SLM Local Engine</span>
          </div>
          <div className="text-[10px] text-slate-400">Zero Cloud API Tokens Required</div>
        </div>
      </div>
    </aside>
  );
};
