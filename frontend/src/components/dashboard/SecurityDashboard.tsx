import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Filter,
  ArrowUpRight,
  Search,
  ExternalLink,
  ChevronRight,
  Clock,
  Layers,
  Sparkles,
  PieChart as PieIcon,
  BarChart3,
  RefreshCw,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  AreaChart,
  Area,
} from 'recharts';
import {
  MOCK_DASHBOARD_FINDINGS,
  PRIORITY_DIST_DATA,
  VULN_TYPE_DATA,
  ACTIVITY_TREND_DATA,
} from '../../data/mockData';
import { FindingSummaryItem, SecurityFindingInput } from '../../types/security';

interface SecurityDashboardProps {
  onLoadFindingToWorkspace: (finding: SecurityFindingInput) => void;
  onOpenAssistant: (contextFinding?: string) => void;
}

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({
  onLoadFindingToWorkspace,
  onOpenAssistant,
}) => {
  const [selectedPriorityFilter, setSelectedPriorityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFindingModal, setSelectedFindingModal] = useState<FindingSummaryItem | null>(null);

  const filteredFindings = MOCK_DASHBOARD_FINDINGS.filter((item) => {
    const matchesPriority =
      selectedPriorityFilter === 'ALL' || item.ml_priority === selectedPriorityFilter;
    const matchesSearch =
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.finding_id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesPriority && matchesSearch;
  });

  return (
    <div className="space-y-8">
      {/* Top Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1 font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Telemetry Center • Real-Time Finding Stream</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-black text-white font-display">
            SECURITY ANALYSIS DASHBOARD
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Holistic vulnerability posture across scanned gateway endpoints and microservices.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs font-mono text-slate-300 flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Updated 2m ago</span>
          </div>
          <span className="text-xs px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 font-mono font-medium">
            Production Fleet
          </span>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        
        {/* Total Findings */}
        <div className="glass-card p-5 rounded-2xl border border-cyan-500/20 col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>TOTAL FINDINGS</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-extrabold text-white font-display">1,248</div>
          <div className="text-[11px] text-emerald-400 mt-2 flex items-center gap-1 font-medium">
            <TrendingUp className="w-3 h-3" />
            <span>+14.2% scanned vs last week</span>
          </div>
        </div>

        {/* Confirmed Vulnerabilities */}
        <div className="glass-card p-5 rounded-2xl border border-rose-500/20">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>CONFIRMED VULNS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-extrabold text-rose-400 font-display">84</div>
          <div className="text-[11px] text-rose-300 mt-2 font-medium">
            Verified scanner verdicts
          </div>
        </div>

        {/* P1 Critical */}
        <div className="glass-card p-5 rounded-2xl border border-rose-600/30 bg-rose-950/20">
          <div className="flex items-center justify-between text-rose-300 text-xs font-mono mb-2">
            <span>CRITICAL (P1)</span>
            <span className="w-2 h-2 rounded-full bg-rose-500 shadow-cyber-p1" />
          </div>
          <div className="text-3xl font-extrabold text-white font-display">18</div>
          <div className="text-[11px] text-rose-300 mt-2 font-medium">
            Immediate mitigation req.
          </div>
        </div>

        {/* P2 High */}
        <div className="glass-card p-5 rounded-2xl border border-amber-500/20 bg-amber-950/10">
          <div className="flex items-center justify-between text-amber-300 text-xs font-mono mb-2">
            <span>HIGH (P2)</span>
            <span className="w-2 h-2 rounded-full bg-amber-400" />
          </div>
          <div className="text-3xl font-extrabold text-white font-display">42</div>
          <div className="text-[11px] text-amber-300 mt-2 font-medium">
            Scheduled sprint priority
          </div>
        </div>

        {/* P3 Medium */}
        <div className="glass-card p-5 rounded-2xl border border-cyan-500/20 bg-cyan-950/10">
          <div className="flex items-center justify-between text-cyan-300 text-xs font-mono mb-2">
            <span>MEDIUM (P3)</span>
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
          </div>
          <div className="text-3xl font-extrabold text-white font-display">24</div>
          <div className="text-[11px] text-cyan-300 mt-2 font-medium">
            Defense-in-depth backlog
          </div>
        </div>

      </div>

      {/* Visual Analytics Grid: Risk Distribution + Vulnerability Types + 7-Day Trend */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Risk Priority Distribution Donut */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <PieIcon className="w-4 h-4 text-cyan-400" />
                <h3 className="text-base font-bold text-white font-display">Risk Priority Distribution</h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                ML Triage Breakdown
              </span>
            </div>

            <div className="h-56 relative flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={PRIORITY_DIST_DATA}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={5}
                    stroke="none"
                  >
                    {PRIORITY_DIST_DATA.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#060b18',
                      borderColor: 'rgba(56, 189, 248, 0.2)',
                      borderRadius: '8px',
                      color: '#fff',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute flex flex-col items-center justify-center pointer-events-none">
                <span className="text-2xl font-black font-display text-white">84</span>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Active</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 pt-4 border-t border-slate-800/80 text-center font-mono">
            {PRIORITY_DIST_DATA.map((item) => (
              <div key={item.name} className="p-2 rounded-xl bg-slate-900/50">
                <div className="text-[10px] text-slate-400">{item.name.split(' ')[0]}</div>
                <div className="text-sm font-bold" style={{ color: item.color }}>
                  {item.value}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability Categories Breakdown Bar Chart */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                <h3 className="text-base font-bold text-white font-display">Vulnerability Types</h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                OWASP Aligned
              </span>
            </div>

            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={VULN_TYPE_DATA} layout="vertical" margin={{ left: -15, right: 10 }}>
                  <XAxis type="number" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={10} width={95} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#060b18',
                      borderColor: 'rgba(56, 189, 248, 0.2)',
                      borderRadius: '8px',
                      color: '#fff',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {VULN_TYPE_DATA.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 font-mono pt-4 border-t border-slate-800/80 flex items-center justify-between">
            <span>Primary Vector: Broken Object Auth</span>
            <span className="text-cyan-400 font-semibold">48 Instances</span>
          </div>
        </div>

        {/* 7-Day Audit Trend Area Chart */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                <h3 className="text-base font-bold text-white font-display">7-Day Audit Activity</h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-500/20">
                1,575 Scanned
              </span>
            </div>

            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={ACTIVITY_TREND_DATA}>
                  <defs>
                    <linearGradient id="colorAudited" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#475569" fontSize={11} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#060b18',
                      borderColor: 'rgba(56, 189, 248, 0.2)',
                      borderRadius: '8px',
                      color: '#fff',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="audited"
                    stroke="#00f0ff"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorAudited)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-slate-800/80 text-xs font-mono">
            <span className="text-slate-400">Peak Scan Velocity:</span>
            <span className="text-cyan-300 font-bold">320 endpoints/hr</span>
          </div>
        </div>

      </div>

      {/* Latest Security Findings Table */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/15">
        
        {/* Table Controls */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h3 className="text-lg font-bold text-white font-display flex items-center gap-2">
              <span>Latest Security Findings</span>
              <span className="px-2 py-0.5 rounded-full bg-slate-800 text-cyan-300 text-xs font-mono">
                {filteredFindings.length}
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Select any finding to view details or send directly to the live AI Analysis Workspace.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter endpoint, ID, type..."
                className="pl-8 pr-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-colors w-48 sm:w-60"
              />
            </div>

            {/* Priority Filters */}
            <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800">
              {['ALL', 'P1', 'P2', 'P3'].map((p) => (
                <button
                  key={p}
                  onClick={() => setSelectedPriorityFilter(p)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium transition-all ${
                    selectedPriorityFilter === p
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
                <th className="py-3 px-3">Finding ID</th>
                <th className="py-3 px-3">Finding Title & Endpoint</th>
                <th className="py-3 px-3">Scanner Verdict</th>
                <th className="py-3 px-3">ML Priority</th>
                <th className="py-3 px-3">Exposure</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  className="hover:bg-cyan-950/20 transition-colors group cursor-pointer"
                  onClick={() => setSelectedFindingModal(finding)}
                >
                  <td className="py-3.5 px-3 font-mono text-cyan-300 font-semibold">
                    {finding.finding_id}
                  </td>
                  <td className="py-3.5 px-3">
                    <div className="font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                      {finding.title}
                    </div>
                    <div className="font-mono text-[11px] text-slate-400 flex items-center gap-2 mt-0.5">
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 text-[10px] font-bold">
                        {finding.http_method}
                      </span>
                      <span className="truncate max-w-xs">{finding.endpoint}</span>
                    </div>
                  </td>
                  <td className="py-3.5 px-3">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium ${
                        finding.scanner_verdict === 'Vulnerability Confirmed'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      }`}
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      {finding.scanner_verdict}
                    </span>
                  </td>
                  <td className="py-3.5 px-3 font-mono">
                    <span
                      className={`px-2 py-1 rounded text-[11px] font-bold ${
                        finding.ml_priority === 'P1'
                          ? 'bg-rose-500 text-slate-950 shadow-cyber-p1'
                          : finding.ml_priority === 'P2'
                          ? 'bg-amber-400 text-slate-950'
                          : 'bg-cyan-400 text-slate-950'
                      }`}
                    >
                      {finding.ml_priority}
                    </span>
                  </td>
                  <td className="py-3.5 px-3 font-mono text-[11px] text-slate-300 uppercase">
                    {finding.exposure.replace('_', ' ')}
                  </td>
                  <td className="py-3.5 px-3">
                    <span className="text-[11px] font-medium text-slate-300">
                      {finding.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onLoadFindingToWorkspace(finding.finding_data);
                      }}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-400/30 text-xs font-mono font-semibold transition-all flex items-center gap-1.5 ml-auto group-hover:border-cyan-300"
                    >
                      <span>Analyze</span>
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </div>

      {/* Inspect Finding Quick Modal */}
      {selectedFindingModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="glass-panel max-w-xl w-full p-6 rounded-2xl border border-cyan-400/30 shadow-2xl relative animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-cyan-400">
                  {selectedFindingModal.finding_id}
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="text-xs text-slate-400">{selectedFindingModal.type.toUpperCase()}</span>
              </div>
              <button
                onClick={() => setSelectedFindingModal(null)}
                className="text-slate-400 hover:text-white p-1 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <div className="py-4 space-y-3">
              <h4 className="text-lg font-bold text-white font-display">
                {selectedFindingModal.title}
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                {selectedFindingModal.finding_data.description}
              </p>

              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-xs text-cyan-200">
                <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-1">
                  Observed Scanner Evidence:
                </div>
                <div className="text-slate-300">{selectedFindingModal.finding_data.evidence}</div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs font-mono pt-2">
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-400 text-[10px]">Scanner Verdict:</span>
                  <div className="font-bold text-rose-400 mt-0.5">
                    {selectedFindingModal.scanner_verdict}
                  </div>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-400 text-[10px]">ML Priority Recommendation:</span>
                  <div className="font-bold text-cyan-400 mt-0.5">
                    {selectedFindingModal.ml_priority} (Trained Classifier)
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800 flex items-center justify-between gap-3">
              <button
                onClick={() => {
                  onOpenAssistant(selectedFindingModal.title);
                  setSelectedFindingModal(null);
                }}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Discuss with AI Assistant</span>
              </button>

              <button
                onClick={() => {
                  onLoadFindingToWorkspace(selectedFindingModal.finding_data);
                  setSelectedFindingModal(null);
                }}
                className="px-5 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs uppercase tracking-wider flex items-center gap-2 shadow-cyber-cyan"
              >
                <span>Open in Live Workspace</span>
                <ArrowUpRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
