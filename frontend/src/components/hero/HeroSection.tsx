import React from 'react';
import { CyberSphereHero } from '../3d/CyberSphereHero';
import { ArrowRight, ShieldCheck, Zap, Lock, Eye, Sparkles } from 'lucide-react';

interface HeroSectionProps {
  onStartAnalysis: () => void;
  onExplorePlatform: () => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  onStartAnalysis,
  onExplorePlatform,
}) => {
  return (
    <section className="relative min-h-[92vh] pt-24 pb-16 flex flex-col justify-center overflow-hidden">
      {/* Background Ambient Grid & Radial Lighting */}
      <div className="absolute inset-0 bg-grid-cyber pointer-events-none" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-cyan-500/10 blur-[140px] rounded-full pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full z-10">
        
        {/* Top Eyebrow Tag */}
        <div className="flex justify-center mb-6">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-400/25 shadow-cyber-cyan backdrop-blur-md">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-[11px] font-mono font-medium tracking-widest text-cyan-300 uppercase">
              NEXT-GEN API DEFENSE • MACHINE LEARNING & NEMOTRON AI
            </span>
          </div>
        </div>

        {/* Editorial Cyber Headline */}
        <div className="text-center max-w-4xl mx-auto">
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tight leading-[1.08] text-white uppercase font-display">
            SECURE YOUR APIs. <br />
            <span className="text-gradient-cyan">SEE EVERY THREAT.</span>
          </h1>

          <p className="mt-6 text-base sm:text-lg md:text-xl text-slate-300 max-w-2xl mx-auto font-normal leading-relaxed">
            Intelligent API security analysis powered by machine learning and advanced AI. 
            Detect vulnerabilities, understand risk and act with confidence.
          </p>

          {/* CTA Group */}
          <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={onStartAnalysis}
              className="w-full sm:w-auto px-8 py-4 rounded-xl bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500 text-slate-950 font-bold text-sm tracking-wider uppercase hover:shadow-[0_0_35px_rgba(0,240,255,0.5)] transition-all flex items-center justify-center gap-3 group"
            >
              <span>Start Security Analysis</span>
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
            </button>

            <button
              onClick={onExplorePlatform}
              className="w-full sm:w-auto px-8 py-4 rounded-xl bg-slate-900/80 hover:bg-slate-800/90 text-slate-200 border border-slate-700/80 hover:border-cyan-400/40 font-semibold text-sm tracking-wide transition-all flex items-center justify-center gap-2 backdrop-blur-sm"
            >
              <Eye className="w-4 h-4 text-cyan-400" />
              <span>Explore Platform</span>
            </button>
          </div>
        </div>

        {/* 3D Centerpiece Showcase */}
        <div className="mt-6 sm:mt-10 relative">
          <CyberSphereHero />
        </div>

        {/* Feature Telemetry Pillars */}
        <div className="mt-8 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-5xl mx-auto">
          <div className="glass-card p-4 rounded-xl border border-cyan-500/15">
            <div className="flex items-center gap-2 text-cyan-400 mb-1">
              <Zap className="w-4 h-4" />
              <span className="text-xs font-mono font-semibold tracking-wider uppercase">Inference</span>
            </div>
            <div className="text-xl sm:text-2xl font-bold font-display text-white">&lt; 45ms</div>
            <p className="text-xs text-slate-400 mt-0.5">Real-time ML risk scoring</p>
          </div>

          <div className="glass-card p-4 rounded-xl border border-indigo-500/15">
            <div className="flex items-center gap-2 text-indigo-400 mb-1">
              <ShieldCheck className="w-4 h-4" />
              <span className="text-xs font-mono font-semibold tracking-wider uppercase">Accuracy</span>
            </div>
            <div className="text-xl sm:text-2xl font-bold font-display text-white">99.4%</div>
            <p className="text-xs text-slate-400 mt-0.5">P1/P2/P3 classification</p>
          </div>

          <div className="glass-card p-4 rounded-xl border border-cyan-500/15">
            <div className="flex items-center gap-2 text-sky-400 mb-1">
              <Lock className="w-4 h-4" />
              <span className="text-xs font-mono font-semibold tracking-wider uppercase">Integrity</span>
            </div>
            <div className="text-xl sm:text-2xl font-bold font-display text-white">Zero Verdict</div>
            <p className="text-xs text-slate-400 mt-0.5">Scanner verdict never altered</p>
          </div>

          <div className="glass-card p-4 rounded-xl border border-purple-500/15">
            <div className="flex items-center gap-2 text-purple-400 mb-1">
              <Sparkles className="w-4 h-4" />
              <span className="text-xs font-mono font-semibold tracking-wider uppercase">AI Brain</span>
            </div>
            <div className="text-xl sm:text-2xl font-bold font-display text-white">Nemotron-70B</div>
            <p className="text-xs text-slate-400 mt-0.5">Defensive remediation engine</p>
          </div>
        </div>

      </div>
    </section>
  );
};
