import React from 'react';
import { Brain, Layers, Binary, Wrench, Shield, CheckCircle2, ChevronRight, AlertTriangle } from 'lucide-react';

interface PlatformOverviewProps {
  onSelectFeature: (featureId: string) => void;
}

export const PlatformOverview: React.FC<PlatformOverviewProps> = ({ onSelectFeature }) => {
  const features = [
    {
      id: 'ai-analysis',
      number: '01',
      title: 'AI-Powered Analysis',
      subtitle: 'Nemotron-powered explanations of API security findings',
      description:
        'Converts complex raw AST findings and HTTP traffic dumps into concise, structured security intelligence. Extracts root-cause architectural weaknesses without hallucinating unobserved vectors.',
      icon: Brain,
      badge: 'NVIDIA Nemotron LLM',
      color: 'from-cyan-500/20 to-blue-600/10',
      borderColor: 'border-cyan-500/30',
      glowColor: 'group-hover:shadow-[0_0_30px_rgba(0,240,255,0.2)]',
      codeSnippet: `// Structured LLM Intelligence
{
  "finding_summary": "BOLA exposed in /v2/users/{id}",
  "evidence_assessment": "Unauthenticated access verified",
  "potential_impact": "Full tenant account takeover"
}`,
    },
    {
      id: 'risk-priority',
      number: '02',
      title: 'Intelligent Risk Prioritization',
      subtitle: 'ML-assisted P1, P2 and P3 priority recommendations',
      description:
        'Trained on enterprise vulnerability telemetry, our ML classifier analyzes exposure vectors, authentication dependencies, data sensitivity, and exploitability to assign balanced P1–P3 priority tiers.',
      icon: Layers,
      badge: 'Trained Random Forest Classifier',
      color: 'from-amber-500/20 to-rose-600/10',
      borderColor: 'border-amber-500/30',
      glowColor: 'group-hover:shadow-[0_0_30px_rgba(245,158,11,0.2)]',
      visualType: 'priorityBars',
    },
    {
      id: 'evidence-detection',
      number: '03',
      title: 'Evidence-Based Detection',
      subtitle: 'Analyze scanner verdicts and supporting evidence',
      description:
        'Maintains absolute scanner verdict immutability. The AI assistant and ML models never override or rewrite your scanner verdict. Machine recommendations are strictly isolated for transparent governance.',
      icon: Binary,
      badge: 'Verdict Immutability Guarantee',
      color: 'from-indigo-500/20 to-purple-600/10',
      borderColor: 'border-indigo-500/30',
      glowColor: 'group-hover:shadow-[0_0_30px_rgba(99,102,241,0.2)]',
      visualType: 'verdictComparison',
    },
    {
      id: 'actionable-remediation',
      number: '04',
      title: 'Actionable Remediation',
      subtitle: 'Generate defensive remediation and validation guidance',
      description:
        'Delivers ready-to-implement defensive patches, middleware authorization policies, and safe validation routines. Zero offensive attack payloads—purely defensive mitigation.',
      icon: Wrench,
      badge: 'Defense & Policy Generator',
      color: 'from-emerald-500/20 to-cyan-600/10',
      borderColor: 'border-emerald-500/30',
      glowColor: 'group-hover:shadow-[0_0_30px_rgba(16,185,129,0.2)]',
      codeSnippet: `// OPA Authorization Policy
default allow = false
allow {
    input.method == "GET"
    input.user_id == input.resource.owner_id
}`,
    },
  ];

  return (
    <section id="overview" className="relative py-28 bg-[#030712] overflow-hidden">
      {/* Ambient background glow */}
      <div className="absolute top-1/2 left-0 w-[450px] h-[450px] bg-blue-600/10 blur-[130px] rounded-full pointer-events-none" />
      <div className="absolute bottom-0 right-0 w-[500px] h-[500px] bg-cyan-500/10 blur-[140px] rounded-full pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-16 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-widest mb-2 font-bold">
              <Shield className="w-4 h-4" />
              <span>Engine Architecture & Capabilities</span>
            </div>
            <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight font-display">
              INTELLIGENCE BUILT FOR <br />
              <span className="text-gradient-cyan">ZERO-TRUST AUDITING</span>
            </h2>
          </div>
          <p className="mt-4 md:mt-0 text-sm sm:text-base text-slate-400 max-w-md font-normal leading-relaxed">
            Eliminate triage fatigue. Correlate raw scanner verdicts with high-precision machine learning prioritization and context-aware LLM remediation.
          </p>
        </div>

        {/* 4 Feature Compositions Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {features.map((feat) => {
            const Icon = feat.icon;
            return (
              <div
                key={feat.id}
                onClick={() => onSelectFeature(feat.id)}
                className={`group relative glass-panel p-8 rounded-2xl border ${feat.borderColor} transition-all duration-300 hover:-translate-y-1 ${feat.glowColor} cursor-pointer flex flex-col justify-between`}
              >
                <div>
                  {/* Top Bar: Number & Badge */}
                  <div className="flex items-center justify-between mb-6">
                    <span className="text-3xl font-black font-display text-slate-700 group-hover:text-cyan-400/80 transition-colors">
                      {feat.number}
                    </span>
                    <span className="px-3 py-1 rounded-full text-xs font-mono font-medium tracking-wide bg-slate-800/80 text-cyan-300 border border-cyan-400/20">
                      {feat.badge}
                    </span>
                  </div>

                  {/* Icon & Title */}
                  <div className="flex items-start gap-4 mb-4">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-400/30 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                      <Icon className="w-6 h-6 text-cyan-400 group-hover:text-cyan-300" />
                    </div>
                    <div>
                      <h3 className="text-xl sm:text-2xl font-bold text-white font-display tracking-tight">
                        {feat.title}
                      </h3>
                      <p className="text-xs font-medium text-cyan-400 mt-0.5">
                        {feat.subtitle}
                      </p>
                    </div>
                  </div>

                  <p className="text-sm text-slate-300 leading-relaxed mb-6">
                    {feat.description}
                  </p>
                </div>

                {/* Interactive Visual Preview on Card */}
                <div className="mt-4 pt-4 border-t border-slate-800/80">
                  {feat.codeSnippet ? (
                    <div className="bg-slate-950/80 rounded-xl p-3 border border-slate-800 text-xs font-mono text-cyan-200 overflow-x-auto">
                      <pre className="text-[11px] leading-snug">{feat.codeSnippet}</pre>
                    </div>
                  ) : feat.visualType === 'priorityBars' ? (
                    <div className="bg-slate-950/80 rounded-xl p-3.5 border border-slate-800 space-y-2">
                      <div className="flex justify-between text-[11px] font-mono">
                        <span className="text-rose-400 font-bold flex items-center gap-1">
                          <span className="w-2 h-2 rounded-full bg-rose-400" /> P1 (Critical Threat)
                        </span>
                        <span className="text-slate-300">72.8%</span>
                      </div>
                      <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div className="bg-rose-500 h-full w-[72.8%]" />
                      </div>

                      <div className="flex justify-between text-[11px] font-mono pt-1">
                        <span className="text-amber-400 font-bold flex items-center gap-1">
                          <span className="w-2 h-2 rounded-full bg-amber-400" /> P2 (Elevated Risk)
                        </span>
                        <span className="text-slate-300">15.0%</span>
                      </div>
                      <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div className="bg-amber-500 h-full w-[15.0%]" />
                      </div>
                    </div>
                  ) : (
                    <div className="bg-slate-950/80 rounded-xl p-3 border border-slate-800 flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span className="text-slate-200">Scanner Verdict: Preserved</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-cyan-400" />
                        <span className="text-cyan-300">ML: Assistive Recommendation</span>
                      </div>
                    </div>
                  )}

                  <div className="mt-4 flex items-center justify-between text-xs text-cyan-400 font-semibold group-hover:text-cyan-300">
                    <span>Inspect Capability</span>
                    <ChevronRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
                  </div>
                </div>

              </div>
            );
          })}
        </div>

      </div>
    </section>
  );
};
