import React, { useState, useEffect } from 'react';
import {
  User,
  Sliders,
  Cpu,
  Server,
  Shield,
  Bell,
  Database,
  Info,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  ExternalLink,
  Download,
  Trash2,
  Save,
} from 'lucide-react';
import { checkBackendHealth } from '../../services/api';

type SettingsTab =
  | 'profile'
  | 'preferences'
  | 'ai'
  | 'api'
  | 'security'
  | 'notifications'
  | 'privacy'
  | 'about';

export const SettingsCenter: React.FC = () => {
  const [activeTab, setActiveTab] = useState<SettingsTab>('profile');

  // Profile Settings
  const [name, setName] = useState('Security Lead');
  const [email, setEmail] = useState('analyst@zynora.ai');
  const [role, setRole] = useState('Staff AppSec Engineer');

  // AI Configuration
  const [aiModel, setAiModel] = useState('nvidia-nemotron-70b');
  const [temperature, setTemperature] = useState(0.2);
  const [maxTokens, setMaxTokens] = useState(2048);
  const [reasoningDepth, setReasoningDepth] = useState('high');

  // API Connections
  const [backendUrl, setBackendUrl] = useState('http://127.0.0.1:8000');
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const [latency, setLatency] = useState<number | null>(null);

  // Security & Human-in-the-Loop
  const [humanApprovalRequired, setHumanApprovalRequired] = useState(true);
  const [safeProbesOnly, setSafeProbesOnly] = useState(true);
  const [strictTenancyCheck, setStrictTenancyCheck] = useState(true);

  // Notifications
  const [notifyOnHighRisk, setNotifyOnHighRisk] = useState(true);
  const [soundFeedback, setSoundFeedback] = useState(true);

  // Save indicator
  const [savedNotice, setSavedNotice] = useState(false);

  // Test backend connection
  const testConnection = async () => {
    setBackendStatus('checking');
    const start = performance.now();
    try {
      const res = await checkBackendHealth();
      const end = performance.now();
      setLatency(Math.round(end - start));
      setBackendStatus(res.online ? 'online' : 'offline');
    } catch {
      setBackendStatus('offline');
      setLatency(null);
    }
  };

  useEffect(() => {
    testConnection();
  }, []);

  const handleSave = () => {
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  const handleExportData = () => {
    const backupData = {
      user: { name, email, role },
      configuration: { aiModel, temperature, reasoningDepth },
      exportedAt: new Date().toISOString(),
      version: 'Zynora-AI-Analyst-v2.4.0',
    };
    const blob = new Blob([JSON.stringify(backupData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `zynora-settings-backup-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="h-full flex flex-col p-4 sm:p-6 md:p-8 overflow-y-auto no-scrollbar font-sans select-none">
      <div className="max-w-5xl w-full mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-200/60">
          <div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 font-heading tracking-tight">
              Settings & Workspace Configuration
            </h1>
            <p className="text-xs sm:text-sm text-slate-500 font-sans mt-0.5">
              Configure AI models, FastAPI engine connectivity, security guardrails, and preferences.
            </p>
          </div>

          <button
            onClick={handleSave}
            className="px-4 py-2 rounded-full bg-gradient-to-r from-pink-500 to-rose-500 hover:opacity-95 text-white text-xs font-semibold flex items-center gap-2 shadow-xs transition-all active:scale-95"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{savedNotice ? 'Saved!' : 'Save Changes'}</span>
          </button>
        </div>

        {/* Tab Navigation Pill Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 bg-white/70 p-1.5 rounded-2xl border border-slate-200/80 shadow-xs">
          {[
            { id: 'profile', label: 'Profile', icon: User },
            { id: 'preferences', label: 'Preferences', icon: Sliders },
            { id: 'ai', label: 'AI Model', icon: Cpu },
            { id: 'api', label: 'API Connect', icon: Server },
            { id: 'security', label: 'Security', icon: Shield },
            { id: 'notifications', label: 'Alerts', icon: Bell },
            { id: 'privacy', label: 'Data', icon: Database },
            { id: 'about', label: 'About', icon: Info },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as SettingsTab)}
                className={`py-2 px-3 rounded-xl text-xs font-medium flex items-center justify-center gap-1.5 transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-pink-500 to-rose-400 text-white font-semibold shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white/80'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Contents */}
        <div className="bg-white/80 backdrop-blur-xl border border-white/90 rounded-2xl p-6 shadow-xs space-y-6">
          
          {/* 1. Profile */}
          {activeTab === 'profile' && (
            <div className="space-y-5">
              <h2 className="text-base font-bold text-slate-800 font-heading">User Profile & Identity</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-700">Display Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-pink-300"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-700">Email Address</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-pink-300"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-700">Assigned Role</label>
                  <input
                    type="text"
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-pink-300"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-700">Organization</label>
                  <input
                    type="text"
                    disabled
                    value="Team Zynora • Hackathon 2026"
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-100 border border-slate-200 text-xs text-slate-500 cursor-not-allowed"
                  />
                </div>
              </div>
            </div>
          )}

          {/* 2. Preferences */}
          {activeTab === 'preferences' && (
            <div className="space-y-5">
              <h2 className="text-base font-bold text-slate-800 font-heading">Interface Preferences</h2>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                  <div>
                    <div className="text-xs font-semibold text-slate-800">Visual Theme</div>
                    <div className="text-[11px] text-slate-500">Soft Ethereal Pastel & Glassmorphism (Dribbble Signature)</div>
                  </div>
                  <span className="text-xs font-mono font-bold text-pink-600">Active</span>
                </div>

                <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                  <div>
                    <div className="text-xs font-semibold text-slate-800">Voice Synthesis Sound Effects</div>
                    <div className="text-[11px] text-slate-500">Audio tones when listening and probe completion</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={soundFeedback}
                    onChange={(e) => setSoundFeedback(e.target.checked)}
                    className="w-4 h-4 text-pink-600 rounded"
                  />
                </div>
              </div>
            </div>
          )}

          {/* 3. AI Configuration */}
          {activeTab === 'ai' && (
            <div className="space-y-5">
              <h2 className="text-base font-bold text-slate-800 font-heading">AI Reasoning Model Configuration</h2>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-700">Primary Reasoning Engine</label>
                  <select
                    value={aiModel}
                    onChange={(e) => setAiModel(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-pink-300"
                  >
                    <option value="nvidia-nemotron-70b">NVIDIA Nemotron 70B (Cybersecurity Fine-Tuned)</option>
                    <option value="zynora-local-slm">Zynora Local SLM Engine (Zero Cloud Latency)</option>
                    <option value="gradient-boost-classifier">Trained ML Priority Classifier (GradientBoost)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-700">Reasoning Depth Mode</label>
                  <select
                    value={reasoningDepth}
                    onChange={(e) => setReasoningDepth(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-pink-300"
                  >
                    <option value="high">Deep Heuristic & AST Code Parsing (Recommended)</option>
                    <option value="standard">Standard Fast Triage</option>
                    <option value="strict">Strict OWASP Compliance Validation</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700">Sampling Temperature</span>
                    <span className="font-mono text-slate-500">{temperature}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={temperature}
                    onChange={(e) => setTemperature(parseFloat(e.target.value))}
                    className="w-full"
                  />
                  <div className="flex justify-between text-[10px] text-slate-400">
                    <span>Deterministic (0.0)</span>
                    <span>Creative (1.0)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-700">Max Analysis Tokens</label>
                  <input
                    type="number"
                    value={maxTokens}
                    onChange={(e) => setMaxTokens(parseInt(e.target.value))}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-800"
                  />
                </div>
              </div>
            </div>
          )}

          {/* 4. API Connections */}
          {activeTab === 'api' && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-bold text-slate-800 font-heading">Backend FastAPI Connections</h2>
                  <p className="text-xs text-slate-500">Live health check and ML model endpoint verification</p>
                </div>
                <button
                  onClick={testConnection}
                  className="px-3 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${backendStatus === 'checking' ? 'animate-spin' : ''}`} />
                  <span>Ping Health</span>
                </button>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-3 h-3 rounded-full ${
                        backendStatus === 'online'
                          ? 'bg-emerald-500 animate-pulse'
                          : backendStatus === 'checking'
                          ? 'bg-amber-400 animate-ping'
                          : 'bg-rose-500'
                      }`}
                    />
                    <span className="font-semibold text-xs text-slate-800 font-mono">
                      {backendUrl}
                    </span>
                  </div>
                  <span
                    className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded-full ${
                      backendStatus === 'online'
                        ? 'bg-emerald-100 text-emerald-700'
                        : 'bg-rose-100 text-rose-700'
                    }`}
                  >
                    {backendStatus.toUpperCase()} {latency ? `(${latency}ms)` : ''}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono text-slate-600 pt-2 border-t border-slate-200">
                  <div>POST /api/v1/analyze: <strong className="text-emerald-600">Available</strong></div>
                  <div>POST /api/v1/chat: <strong className="text-emerald-600">Available</strong></div>
                  <div>GET /health: <strong className="text-emerald-600">200 OK</strong></div>
                </div>
              </div>
            </div>
          )}

          {/* 5. Security & Human-in-the-Loop */}
          {activeTab === 'security' && (
            <div className="space-y-5">
              <h2 className="text-base font-bold text-slate-800 font-heading">Human-in-the-Loop Guardrails</h2>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                  <div>
                    <div className="text-xs font-semibold text-slate-800">Mandatory Human Operator Approval</div>
                    <div className="text-[11px] text-slate-500">Require operator consent before any probe payload executes</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={humanApprovalRequired}
                    onChange={(e) => setHumanApprovalRequired(e.target.checked)}
                    className="w-4 h-4 text-pink-600 rounded"
                  />
                </div>

                <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                  <div>
                    <div className="text-xs font-semibold text-slate-800">Non-Destructive Probe Safety Flag</div>
                    <div className="text-[11px] text-slate-500">Enforces read-only assertions; blocks state-mutating drops or truncates</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={safeProbesOnly}
                    onChange={(e) => setSafeProbesOnly(e.target.checked)}
                    className="w-4 h-4 text-pink-600 rounded"
                  />
                </div>

                <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                  <div>
                    <div className="text-xs font-semibold text-slate-800">Strict Tenant Isolation Guard</div>
                    <div className="text-[11px] text-slate-500">Automatically flags cross-tenant URI parameter mismatches as P1</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={strictTenancyCheck}
                    onChange={(e) => setStrictTenancyCheck(e.target.checked)}
                    className="w-4 h-4 text-pink-600 rounded"
                  />
                </div>
              </div>
            </div>
          )}

          {/* 6. Notifications */}
          {activeTab === 'notifications' && (
            <div className="space-y-5">
              <h2 className="text-base font-bold text-slate-800 font-heading">Notification & Alert Rules</h2>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                  <div>
                    <div className="text-xs font-semibold text-slate-800">High Risk (P1) Vulnerability Alerts</div>
                    <div className="text-[11px] text-slate-500">Highlight immediate BOLA/BFLA critical findings</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifyOnHighRisk}
                    onChange={(e) => setNotifyOnHighRisk(e.target.checked)}
                    className="w-4 h-4 text-pink-600 rounded"
                  />
                </div>
              </div>
            </div>
          )}

          {/* 7. Data & Privacy */}
          {activeTab === 'privacy' && (
            <div className="space-y-5">
              <h2 className="text-base font-bold text-slate-800 font-heading">Data & Local Storage Management</h2>
              <p className="text-xs text-slate-500">Export chat history or clear session telemetry safely.</p>
              
              <div className="flex items-center gap-3">
                <button
                  onClick={handleExportData}
                  className="px-4 py-2 rounded-xl bg-white border border-slate-200 hover:border-pink-300 text-xs font-semibold text-slate-800 flex items-center gap-2 shadow-xs transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-pink-500" />
                  <span>Export Workspace Backup (JSON)</span>
                </button>
              </div>
            </div>
          )}

          {/* 8. About */}
          {activeTab === 'about' && (
            <div className="space-y-4">
              <h2 className="text-base font-bold text-slate-800 font-heading">About Zynora AI Security Analyst</h2>
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 space-y-2 text-xs text-slate-700 leading-relaxed">
                <div><strong>Application:</strong> Zynora AI API Security Analyst</div>
                <div><strong>Version:</strong> 2.4.0 (Hackathon Enterprise Edition)</div>
                <div><strong>ML Core:</strong> GradientBoosted Priority Classifier (`priority_model.joblib`)</div>
                <div><strong>Inference Backend:</strong> FastAPI + NVIDIA Nemotron Integration (`http://127.0.0.1:8000`)</div>
                <div><strong>UI Framework:</strong> React 19, Vite 6, Tailwind CSS, Three.js, Lucide Icons</div>
                <div className="pt-2 text-[11px] text-slate-500">
                  Designed for automated, human-in-the-loop API security auditing, BOLA identification, and zero-loss defense validation.
                </div>
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
};
