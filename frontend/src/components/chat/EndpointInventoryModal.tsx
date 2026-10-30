import React, { useState } from 'react';
import {
  X,
  Search,
  Layers,
  Lock,
  Unlock,
  ArrowRight,
} from 'lucide-react';
import type { ApiSpec, ApiEndpoint } from '../../types/assistant';

interface EndpointInventoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  spec: ApiSpec | null;
  onProposeEndpointTest: (endpoint: ApiEndpoint) => void;
}

export const EndpointInventoryModal: React.FC<EndpointInventoryModalProps> = ({
  isOpen,
  onClose,
  spec,
  onProposeEndpointTest,
}) => {
  if (!isOpen || !spec) return null;

  const [searchQuery, setSearchQuery] = useState('');
  const [methodFilter, setMethodFilter] = useState('ALL');

  const filteredEndpoints = spec.endpoints.filter((ep) => {
    const matchesSearch =
      ep.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ep.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ep.potentialRisks.some((r) => r.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesMethod = methodFilter === 'ALL' || ep.method === methodFilter;
    return matchesSearch && matchesMethod;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200 text-slate-800">
        
        {/* Modal Header */}
        <div className="h-16 px-6 border-b border-slate-100 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-sky-100 border border-sky-200 flex items-center justify-center text-sky-600 shadow-xs">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 font-display">
                Endpoint Inventory: {spec.title}
              </h3>
              <p className="text-xs font-mono text-slate-500">
                {spec.endpoints.length} Total Parsed Endpoints • Base URL: {spec.baseUrl}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Search & Filters */}
        <div className="px-6 py-3 border-b border-slate-100 bg-slate-50/70 flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by path, summary, or vulnerability type..."
              className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-white border border-slate-200 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-sky-400 shadow-xs"
            />
          </div>

          <div className="flex items-center gap-1 bg-white p-1 rounded-xl border border-slate-200 shadow-xs">
            {['ALL', 'GET', 'POST', 'PUT', 'DELETE'].map((m) => (
              <button
                key={m}
                onClick={() => setMethodFilter(m)}
                className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium transition-all ${
                  methodFilter === m
                    ? 'bg-sky-100 text-sky-700 font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>

        {/* Endpoints List */}
        <div className="flex-1 overflow-y-auto p-6 divide-y divide-slate-100 space-y-4">
          {filteredEndpoints.length > 0 ? (
            filteredEndpoints.map((ep) => (
              <div key={ep.id} className="pt-4 first:pt-0 group">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-start gap-3 flex-1">
                    <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-100 text-slate-700 shrink-0 mt-0.5">
                      {ep.method}
                    </span>
                    <div className="space-y-1">
                      <div className="font-mono text-xs sm:text-sm font-semibold text-slate-900 flex items-center gap-2">
                        <span>{ep.path}</span>
                        {ep.authRequired ? (
                          <span className="flex items-center gap-1 text-[10px] text-emerald-700 font-mono">
                            <Lock className="w-3 h-3 text-emerald-600" />
                            <span>Protected</span>
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-[10px] text-amber-700 font-mono">
                            <Unlock className="w-3 h-3 text-amber-600" />
                            <span>Public</span>
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-600">{ep.summary}</p>
                      
                      {/* Potential Risks */}
                      <div className="flex items-center gap-1.5 flex-wrap pt-1">
                        {ep.potentialRisks.map((risk, rIdx) => (
                          <span
                            key={rIdx}
                            className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-50 text-rose-700 border border-rose-200"
                          >
                            {risk}
                          </span>
                        ))}
                        {ep.parameters.length > 0 && (
                          <span className="text-[10px] font-mono text-slate-400">
                            • {ep.parameters.length} parameter{ep.parameters.length > 1 ? 's' : ''} ({ep.parameters.map((p) => p.name).join(', ')})
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={() => {
                      onProposeEndpointTest(ep);
                      onClose();
                    }}
                    className="px-3.5 py-1.5 rounded-xl bg-sky-50 hover:bg-sky-100 text-sky-700 border border-sky-200 text-xs font-mono font-semibold transition-all flex items-center gap-1.5 shrink-0 ml-auto shadow-xs"
                  >
                    <span>Propose Test</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-12 text-slate-400 text-xs font-mono">
              No endpoints match your search criteria.
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="h-14 px-6 border-t border-slate-100 bg-slate-50/70 flex items-center justify-between text-xs font-mono text-slate-500 shrink-0">
          <span>Showing {filteredEndpoints.length} of {spec.endpoints.length} Endpoints</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 transition-colors shadow-xs"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
