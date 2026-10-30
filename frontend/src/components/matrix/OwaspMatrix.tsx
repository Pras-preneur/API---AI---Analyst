import React from 'react';
import { Shield, ArrowUpRight } from 'lucide-react';
import type { SecurityFindingInput } from '../../types/security';

interface OwaspMatrixProps {
  onLoadTemplate: (finding: SecurityFindingInput) => void;
}

export const OwaspMatrix: React.FC<OwaspMatrixProps> = () => {
  const owaspCategories = [
    {
      code: 'API1:2023',
      name: 'Broken Object Level Authorization (BOLA)',
      risk: 'CRITICAL',
      riskColor: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
      description:
        'Attackers manipulate the ID of an object sent within the request to gain unauthorized access to data belonging to other users.',
      platformDefense:
        'ML evaluates lack of tenant token checks as P1. Generates object-level ownership assertions and OPA policies.',
      sampleEndpoint: '/api/v2/users/{id}/financial-records',
    },
    {
      code: 'API2:2023',
      name: 'Broken Authentication',
      risk: 'HIGH',
      riskColor: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
      description:
        'Poorly implemented authentication mechanisms allow credential stuffing, token theft, or forged claims.',
      platformDefense:
        'Detects lack of token verification headers, validates signature enforcement, and flags missing auth requirements.',
      sampleEndpoint: '/api/v1/auth/tokens/refresh',
    },
    {
      code: 'API3:2023',
      name: 'Broken Object Property Level Authorization',
      risk: 'HIGH',
      riskColor: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
      description:
        'Combines Excessive Data Exposure and Mass Assignment. Endpoint exposes sensitive properties or accepts unauthorized field updates.',
      platformDefense:
        'Analyzes DTO serialization schemas and outbound masks to prevent leaks of SSN, hashes, and audit parameters.',
      sampleEndpoint: '/api/v3/profile/settings',
    },
    {
      code: 'API4:2023',
      name: 'Unrestricted Resource Consumption',
      risk: 'MEDIUM',
      riskColor: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
      description:
        'Lack of execution timeouts, memory limits, or rate limits leading to Denial of Service (DoS) or excessive compute bills.',
      platformDefense:
        'Assesses pagination bounds, regex complexity (ReDoS), and suggests token bucket rate limiting thresholds.',
      sampleEndpoint: '/api/v1/search/catalog',
    },
    {
      code: 'API5:2023',
      name: 'Broken Function Level Authorization (BFLA)',
      risk: 'CRITICAL',
      riskColor: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
      description:
        'Unprivileged users invoke administrative routines due to missing role and permission gates.',
      platformDefense:
        'ML prioritizes high-privilege administrative URIs invoked by regular roles as P1/P2. Recommends strict RBAC middleware.',
      sampleEndpoint: '/api/v1/admin/tenants/export',
    },
    {
      code: 'API8:2023',
      name: 'Security Misconfiguration',
      risk: 'HIGH',
      riskColor: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
      description:
        'Unpatched systems, exposed debug routes, open cloud storage, or permissive CORS configurations.',
      platformDefense:
        'Detects active /debug routes and secret disclosure (API keys, DB connection strings), recommending immediate gateway blocking.',
      sampleEndpoint: '/debug/metrics/env-dump',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-widest mb-1 font-bold">
            <Shield className="w-4 h-4" />
            <span>Standardized Threat Taxonomy</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-black text-white font-display">
            OWASP API SECURITY TOP 10 (2023)
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            How API Security Analyst triages and mitigates industry-standard vulnerability classes.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Source: OWASP Foundation API Security Project
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {owaspCategories.map((item) => (
          <div
            key={item.code}
            className="glass-panel p-6 rounded-2xl border border-cyan-500/15 flex flex-col justify-between hover:border-cyan-400/40 transition-all hover:-translate-y-1 group"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-xs font-bold text-cyan-400">{item.code}</span>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${item.riskColor}`}
                >
                  {item.risk}
                </span>
              </div>

              <h3 className="text-lg font-bold text-white font-display group-hover:text-cyan-300 transition-colors">
                {item.name}
              </h3>

              <p className="text-xs text-slate-300 mt-2.5 leading-relaxed font-sans">
                {item.description}
              </p>

              <div className="mt-4 pt-4 border-t border-slate-800/80">
                <div className="text-[10px] font-mono uppercase tracking-widest text-slate-400 mb-1 font-semibold">
                  Platform Defense & ML Handling:
                </div>
                <p className="text-xs text-cyan-200/90 leading-relaxed font-mono">
                  {item.platformDefense}
                </p>
              </div>
            </div>

            <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-400 truncate max-w-[180px]">
                {item.sampleEndpoint}
              </span>
              <span className="text-xs text-cyan-400 font-mono font-semibold flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                <span>Threat Map</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
