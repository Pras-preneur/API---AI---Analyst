import React, { useState, useEffect } from 'react';
import { Shield, Activity, Terminal, Sparkles, Menu, X, ArrowUpRight, Cpu } from 'lucide-react';
import { checkBackendHealth } from '../../services/api';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenQuickScan: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, onOpenQuickScan }) => {
  const [backendStatus, setBackendStatus] = useState<{ online: boolean; message: string }>({
    online: false,
    message: 'Checking...',
  });
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const testHealth = async () => {
      const res = await checkBackendHealth();
      if (isMounted) {
        setBackendStatus({ online: res.online, message: res.online ? 'FastAPI Online :8000' : 'Backend Standby' });
      }
    };

    testHealth();
    const interval = setInterval(testHealth, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { id: 'hero', label: 'Platform' },
    { id: 'overview', label: 'Capabilities' },
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'workspace', label: 'Analysis Workspace' },
    { id: 'assistant', label: 'AI Assistant' },
    { id: 'matrix', label: 'OWASP Matrix' },
  ];

  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-[#030712]/80 backdrop-blur-xl border-b border-cyan-500/10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-20">
          
          {/* Brand Logo */}
          <div 
            onClick={() => setActiveTab('hero')} 
            className="flex items-center gap-3 cursor-pointer group select-none"
          >
            <div className="relative w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-400/30 flex items-center justify-center shadow-cyber-cyan transition-transform group-hover:scale-105">
              <Shield className="w-5 h-5 text-cyan-400 transition-colors group-hover:text-cyan-300" />
              <div className="absolute inset-0 rounded-xl bg-cyan-400/10 blur-[6px] opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-base tracking-wider text-slate-100 font-display">
                  API SECURITY
                </span>
                <span className="text-cyan-400 font-extrabold text-base tracking-wider font-display">
                  ANALYST
                </span>
              </div>
              <div className="text-[10px] tracking-widest text-slate-400 uppercase font-mono flex items-center gap-1">
                <span>AI-Assisted Triage</span>
                <span className="text-cyan-400/60">•</span>
                <span className="text-cyan-300/80 font-medium">v1.0</span>
              </div>
            </div>
          </div>

          {/* Desktop Navigation */}
          <nav className="hidden lg:flex items-center gap-1 bg-slate-900/60 p-1.5 rounded-full border border-slate-800">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`relative px-4 py-1.5 rounded-full text-xs font-medium tracking-wide transition-all ${
                    isActive
                      ? 'text-cyan-300 bg-cyan-500/15 border border-cyan-400/30 shadow-cyber-cyan font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  {item.label}
                  {item.id === 'workspace' && (
                    <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[9px] bg-cyan-500/30 text-cyan-300 font-mono">
                      LIVE
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Action & Telemetry */}
          <div className="hidden sm:flex items-center gap-4">
            
            {/* Backend Health Badge */}
            <div 
              title="FastAPI server connection status at http://127.0.0.1:8000"
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono"
            >
              <span className={`w-2 h-2 rounded-full ${backendStatus.online ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-amber-400/80'} animate-pulse`} />
              <span className="text-slate-300 text-[11px] font-medium">{backendStatus.message}</span>
            </div>

            {/* Quick Analyze CTA */}
            <button
              onClick={onOpenQuickScan}
              className="relative group px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs tracking-wider uppercase transition-all shadow-cyber-cyan hover:shadow-cyan-400/40 flex items-center gap-2"
            >
              <Cpu className="w-3.5 h-3.5 text-slate-950" />
              <span>Analyze API</span>
              <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </button>
          </div>

          {/* Mobile Menu Button */}
          <div className="lg:hidden flex items-center gap-2">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-300 hover:text-white"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="lg:hidden bg-slate-950/95 border-b border-cyan-500/20 px-4 pt-3 pb-6 space-y-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveTab(item.id);
                setMobileMenuOpen(false);
              }}
              className={`w-full text-left px-4 py-2.5 rounded-lg text-sm font-medium ${
                activeTab === item.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30'
                  : 'text-slate-300 hover:bg-slate-900'
              }`}
            >
              {item.label}
            </button>
          ))}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">{backendStatus.message}</span>
            <button
              onClick={() => {
                onOpenQuickScan();
                setMobileMenuOpen(false);
              }}
              className="px-4 py-2 rounded-lg bg-cyan-400 text-slate-950 font-semibold text-xs uppercase"
            >
              Analyze API
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
