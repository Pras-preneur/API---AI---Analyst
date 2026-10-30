import React from 'react';
import {
  Menu,
  FileCode,
  Layers,
  FileDown,
  Upload,
} from 'lucide-react';
import type { ApiSpec } from '../../types/assistant';

interface ChatHeaderProps {
  onToggleSidebar: () => void;
  activeSpec: ApiSpec | null;
  onOpenInventory: () => void;
  onOpenUpload: () => void;
  onOpenReport: () => void;
  backendOnline: boolean;
}

export const ChatHeader: React.FC<ChatHeaderProps> = ({
  onToggleSidebar,
  activeSpec,
  onOpenInventory,
  onOpenUpload,
  onOpenReport,
  backendOnline,
}) => {
  return (
    <header className="h-16 px-4 sm:px-6 bg-white/90 backdrop-blur-md border-b border-slate-200/80 flex items-center justify-between shrink-0 z-30 shadow-[0_1px_3px_rgba(0,0,0,0.03)]">
      
      {/* Left: Mobile Toggle & Active Spec Indicator */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="p-2 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 lg:hidden transition-colors"
          title="Toggle Navigation Sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>

        {activeSpec ? (
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-50 border border-slate-200 text-xs text-slate-700 shadow-sm">
              <FileCode className="w-3.5 h-3.5 text-sky-500" />
              <span className="font-semibold truncate max-w-[180px] sm:max-w-xs">{activeSpec.title}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-sky-100 text-sky-700 font-bold">
                {activeSpec.endpoints.length} Endpoints
              </span>
            </div>

            <button
              onClick={onOpenInventory}
              className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono text-sky-700 hover:bg-sky-50 border border-sky-200/80 hover:border-sky-300 transition-colors"
              title="Inspect parsed endpoints and parameters"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Inspect Inventory</span>
            </button>
          </div>
        ) : (
          <div className="text-xs text-slate-500 font-mono">
            No specification loaded. Upload an OpenAPI JSON/YAML to begin.
          </div>
        )}
      </div>

      {/* Right: Actions & Status */}
      <div className="flex items-center gap-2.5">
        
        {/* Upload Spec Action */}
        <button
          onClick={onOpenUpload}
          className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm hover:border-sky-200"
        >
          <Upload className="w-3.5 h-3.5 text-sky-500" />
          <span className="hidden sm:inline">Upload Spec</span>
        </button>

        {/* Export Report Action */}
        <button
          onClick={onOpenReport}
          className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm hover:border-purple-200"
        >
          <FileDown className="w-3.5 h-3.5 text-purple-500" />
          <span className="hidden sm:inline">Assessment Report</span>
        </button>

        {/* Backend SLM Status */}
        <div 
          title="Local Small Language Model & FastAPI Engine Status"
          className="hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono text-slate-600 shadow-sm"
        >
          <span className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-500' : 'bg-amber-500'} animate-pulse`} />
          <span>Local SLM Engine</span>
        </div>

      </div>

    </header>
  );
};
