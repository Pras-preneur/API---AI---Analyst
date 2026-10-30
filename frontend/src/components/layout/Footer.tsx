import React from 'react';
import { Shield, Cpu, ExternalLink, Heart, Terminal, Sparkles } from 'lucide-react';

interface FooterProps {
  setActiveTab: (tab: string) => void;
}

export const Footer: React.FC<FooterProps> = ({ setActiveTab }) => {
  return (
    <footer className="relative bg-[#02050e] border-t border-cyan-500/10 pt-16 pb-12 overflow-hidden text-xs text-slate-400">
      {/* Ambient background glow */}
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-cyan-500/5 blur-[140px] rounded-full pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12 pb-12 border-b border-slate-800/80">
          
          {/* Col 1: Brand & Mission */}
          <div className="md:col-span-2 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-400/30 flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
              <span className="font-extrabold text-lg tracking-wider text-white font-display">
                API SECURITY <span className="text-cyan-400">ANALYST</span>
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-sm leading-relaxed">
              AI-assisted triage and vulnerability intelligence for mission-critical APIs. 
              Preserving scanner veracity with immutable governance and intelligent prioritization.
            </p>
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>FastAPI Backend • NVIDIA Nemotron • Scikit-learn Classifier</span>
            </div>
          </div>

          {/* Col 2: Navigation Links */}
          <div className="space-y-3 font-mono">
            <div className="text-white font-bold text-xs uppercase tracking-wider">Navigation</div>
            <ul className="space-y-2">
              <li>
                <button onClick={() => setActiveTab('hero')} className="hover:text-cyan-300 transition-colors">
                  01. Platform Showcase
                </button>
              </li>
              <li>
                <button onClick={() => setActiveTab('overview')} className="hover:text-cyan-300 transition-colors">
                  02. Engine Capabilities
                </button>
              </li>
              <li>
                <button onClick={() => setActiveTab('dashboard')} className="hover:text-cyan-300 transition-colors">
                  03. Security Dashboard
                </button>
              </li>
              <li>
                <button onClick={() => setActiveTab('workspace')} className="hover:text-cyan-300 transition-colors">
                  04. Analysis Workspace
                </button>
              </li>
              <li>
                <button onClick={() => setActiveTab('assistant')} className="hover:text-cyan-300 transition-colors">
                  05. AI Security Copilot
                </button>
              </li>
            </ul>
          </div>

          {/* Col 3: Architecture & Governance */}
          <div className="space-y-3 font-mono">
            <div className="text-white font-bold text-xs uppercase tracking-wider">Zero-Trust Boundaries</div>
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] leading-relaxed text-slate-300">
              Rule 1: Scanner verdicts are immutable. <br />
              Rule 2: ML Priority is an assistive recommendation. <br />
              Rule 3: Remediation is strictly defensive.
            </div>
          </div>

        </div>

        {/* Bottom bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-[11px]">
          <div>
            © 2026 API Security Analyst. Developed for Hackathon Excellence.
          </div>
          <div className="flex items-center gap-4 text-slate-500">
            <span>FastAPI:8000</span>
            <span>•</span>
            <span>Three.js WebGL</span>
            <span>•</span>
            <span className="text-cyan-400 font-semibold">Pixel-Perfect Standard</span>
          </div>
        </div>

      </div>
    </footer>
  );
};
