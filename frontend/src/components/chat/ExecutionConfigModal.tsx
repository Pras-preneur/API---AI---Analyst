import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Play,
  X,
  Lock,
  User,
  Sliders,
  CheckCircle2,
  Info,
} from 'lucide-react';
import type {
  BackendExecutionConfig,
  BackendTestIdentity,
  BackendParameterFixtures,
} from '../../types/backend';
import type { ProposedTest } from '../../types/assistant';

interface ExecutionConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  proposals: ProposedTest[];
  onExecute: (selectedProposalIds: string[], config: BackendExecutionConfig) => Promise<void>;
  isExecuting: boolean;
}

const AUTHORIZED_TARGET = 'http://127.0.0.1:8001';

export const ExecutionConfigModal: React.FC<ExecutionConfigModalProps> = ({
  isOpen,
  onClose,
  proposals,
  onExecute,
  isExecuting,
}) => {
  // 1. Proposal Selection State
  const [selectedIds, setSelectedIds] = useState<Record<string, boolean>>({});

  // 2. Budget & Timeout
  const [maxRequests, setMaxRequests] = useState<number>(10);

  // 3. Sensitive Identity State (IN-MEMORY ONLY; strictly cleared on close/execution)
  const [authIdentityId, setAuthIdentityId] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [authVerified, setAuthVerified] = useState(true);

  // BOLA Personas
  const [ownerId, setOwnerId] = useState('');
  const [ownerToken, setOwnerToken] = useState('');
  const [ownerParamKey, setOwnerParamKey] = useState('user_id');
  const [ownerParamVal, setOwnerParamVal] = useState('');
  const [attackerId, setAttackerId] = useState('');
  const [attackerToken, setAttackerToken] = useState('');

  // BFLA Personas & Policy
  const [privId, setPrivId] = useState('');
  const [privRole, setPrivRole] = useState('admin');
  const [privToken, setPrivToken] = useState('');
  const [lowerId, setLowerId] = useState('');
  const [lowerRole, setLowerRole] = useState('user');
  const [lowerToken, setLowerToken] = useState('');
  const [bflaEndpoint, setBflaEndpoint] = useState('');
  const [bflaRequiredRole, setBflaRequiredRole] = useState('admin');

  // Error state
  const [validationError, setValidationError] = useState<string | null>(null);

  // Reset sensitive credentials on modal close or unmount
  const wipeSensitiveState = () => {
    setAuthIdentityId('');
    setAuthToken('');
    setAuthVerified(true);
    setOwnerId('');
    setOwnerToken('');
    setOwnerParamKey('user_id');
    setOwnerParamVal('');
    setAttackerId('');
    setAttackerToken('');
    setPrivId('');
    setPrivRole('admin');
    setPrivToken('');
    setLowerId('');
    setLowerRole('user');
    setLowerToken('');
    setBflaEndpoint('');
    setBflaRequiredRole('admin');
    setValidationError(null);
  };

  const handleClose = () => {
    wipeSensitiveState();
    onClose();
  };

  // Inspect eligible vs unsupported proposals
  // Supported in SPEC_DRIVEN mode: AUTH_MISSING_CREDENTIALS, BOLA, BFLA
  const isSupportedType = (testType: string) => {
    const norm = testType.toLowerCase();
    return norm.includes('auth') || norm === 'bola' || norm === 'bfla';
  };

  const approvedProposals = proposals.filter((p) => p.status === 'approved');
  const eligibleProposals = approvedProposals.filter((p) => isSupportedType(p.vulnerabilityType));
  const unsupportedProposals = approvedProposals.filter((p) => !isSupportedType(p.vulnerabilityType));

  // Initialize selection when modal opens
  useEffect(() => {
    if (isOpen) {
      const initial: Record<string, boolean> = {};
      eligibleProposals.forEach((p) => {
        initial[p.testId] = true;
      });
      setSelectedIds(initial);

      // Pre-fill BFLA endpoint if any BFLA test is in proposals
      const bflaTest = eligibleProposals.find((p) => p.vulnerabilityType.toLowerCase() === 'bfla');
      if (bflaTest) {
        setBflaEndpoint(bflaTest.endpoint);
      }
    } else {
      wipeSensitiveState();
    }
  }, [isOpen, proposals.length]);

  if (!isOpen) return null;

  const toggleSelect = (testId: string) => {
    setSelectedIds((prev) => ({
      ...prev,
      [testId]: !prev[testId],
    }));
  };

  const selectedProposalIds = Object.keys(selectedIds).filter((id) => selectedIds[id]);
  const selectedTests = eligibleProposals.filter((p) => selectedIds[p.testId]);

  const hasAuth = selectedTests.some((p) => p.vulnerabilityType.toLowerCase().includes('auth'));
  const hasBola = selectedTests.some((p) => p.vulnerabilityType.toLowerCase() === 'bola');
  const hasBfla = selectedTests.some((p) => p.vulnerabilityType.toLowerCase() === 'bfla');

  const handleExecuteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    if (selectedProposalIds.length === 0) {
      setValidationError('At least one approved security proposal must be selected for execution.');
      return;
    }

    if (maxRequests < 1 || maxRequests > 10) {
      setValidationError('Request budget must be between 1 and 10 requests.');
      return;
    }

    // Build ExecutionConfig
    const config: BackendExecutionConfig = {
      mode: 'SPEC_DRIVEN',
      target_base_url: AUTHORIZED_TARGET,
      follow_redirects: false, // Mandatory
      require_approval: true, // Mandatory
      budget: {
        max_requests: maxRequests,
      },
    };

    // 1. Validate and attach Auth Identity if needed
    if (hasAuth) {
      const trimId = authIdentityId.trim();
      const trimToken = authToken.trim();
      if (!trimId) {
        setValidationError('Authentication testing requires a valid Authenticated Identity ID (e.g. alice).');
        return;
      }
      if (!trimToken) {
        setValidationError('Authentication testing requires an authenticated baseline token or credential.');
        return;
      }
      if (!authVerified) {
        setValidationError('The backend requires verification that credentials are valid (credentials_verified=true).');
        return;
      }

      config.authenticated_identity = {
        identity_id: trimId,
        username: trimId,
        token: trimToken,
        credentials_verified: true,
        roles: ['user'],
      };
    }

    // 2. Validate and attach BOLA Identities if needed
    if (hasBola) {
      const trimOwnerId = ownerId.trim();
      const trimOwnerToken = ownerToken.trim();
      const trimAttackerId = attackerId.trim();
      const trimAttackerToken = attackerToken.trim();

      if (!trimOwnerId || !trimOwnerToken) {
        setValidationError('BOLA testing requires Resource Owner Identity (ID and Token).');
        return;
      }
      if (!trimAttackerId || !trimAttackerToken) {
        setValidationError('BOLA testing requires Attacker Identity (ID and Token).');
        return;
      }
      if (trimOwnerToken === trimAttackerToken) {
        setValidationError('Credential Isolation Violation: Owner and Attacker cannot share identical credentials.');
        return;
      }
      if (!ownerParamKey.trim() || !ownerParamVal.trim()) {
        setValidationError('BOLA testing requires owner path parameter fixtures (e.g. user_id = 101).');
        return;
      }

      config.owner_identity = {
        identity_id: trimOwnerId,
        token: trimOwnerToken,
        credentials_verified: true,
        roles: ['user'],
      };
      config.attacker_identity = {
        identity_id: trimAttackerId,
        token: trimAttackerToken,
        credentials_verified: true,
        roles: ['attacker'],
      };

      const params: BackendParameterFixtures = {
        owner_path_params: { [ownerParamKey.trim()]: ownerParamVal.trim() },
        attacker_path_params: { [ownerParamKey.trim()]: ownerParamVal.trim() },
      };
      config.parameters = params;
    }

    // 3. Validate and attach BFLA Identities if needed
    if (hasBfla) {
      const trimPrivId = privId.trim();
      const trimPrivToken = privToken.trim();
      const trimLowerId = lowerId.trim();
      const trimLowerToken = lowerToken.trim();

      if (!trimPrivId || !trimPrivToken) {
        setValidationError('BFLA testing requires Privileged Identity (Admin).');
        return;
      }
      if (!trimLowerId || !trimLowerToken) {
        setValidationError('BFLA testing requires Lower-Privileged Identity (User).');
        return;
      }
      if (trimPrivToken === trimLowerToken) {
        setValidationError('Credential Isolation Violation: Privileged and Lower-Privileged personas cannot share identical credentials.');
        return;
      }

      config.privileged_identity = {
        identity_id: trimPrivId,
        token: trimPrivToken,
        roles: [privRole.trim()],
        credentials_verified: true,
      };
      config.lower_privileged_identity = {
        identity_id: trimLowerId,
        token: trimLowerToken,
        roles: [lowerRole.trim()],
        credentials_verified: true,
      };

      config.bfla_policy = {
        endpoint_path: bflaEndpoint.trim() || '/admin/data',
        endpoint_method: 'GET',
        required_role: bflaRequiredRole.trim() || 'admin',
        permitted_roles: [bflaRequiredRole.trim() || 'admin'],
        forbidden_roles: [lowerRole.trim() || 'user'],
      };
    }

    try {
      await onExecute(selectedProposalIds, config);
      wipeSensitiveState();
      onClose();
    } catch (err: any) {
      setValidationError(err?.message || 'Execution request failed.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl max-h-[90vh] bg-[#121622] border border-slate-700/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-200 font-sans">
        
        {/* Modal Header */}
        <div className="px-5 py-3.5 border-b border-slate-700/70 flex items-center justify-between bg-[#161a28]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-pink-900/40 border border-pink-700/60 flex items-center justify-center text-pink-400">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>Controlled Execution Engine</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800">
                  SPEC_DRIVEN
                </span>
              </h2>
              <p className="text-[11px] text-slate-400 font-mono">
                Target: <span className="text-pink-300 font-semibold">{AUTHORIZED_TARGET}</span> • Sandbox Guardrails Active
              </p>
            </div>
          </div>

          <button
            onClick={handleClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 transition-colors"
            title="Cancel and wipe credentials"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body: Scrollable */}
        <form onSubmit={handleExecuteSubmit} className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
          {validationError && (
            <div className="p-3 rounded-xl bg-rose-950/80 border border-rose-700/80 text-rose-200 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <strong>Execution Guardrail Warning: </strong>
                <span>{validationError}</span>
              </div>
            </div>
          )}

          {/* Section 1: Proposal Selection */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-pink-500" />
                <span>Select Approved Proposals for Execution</span>
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-pink-300 border border-slate-700">
                {selectedProposalIds.length} of {eligibleProposals.length} eligible selected
              </span>
            </div>

            {eligibleProposals.length === 0 ? (
              <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-800/50 text-amber-300 text-xs">
                No approved supported proposals found. Please approve proposals in the chat first.
              </div>
            ) : (
              <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                {eligibleProposals.map((prop) => (
                  <label
                    key={prop.testId}
                    className={`flex items-center justify-between p-2 rounded-lg border transition-all cursor-pointer ${
                      selectedIds[prop.testId]
                        ? 'bg-[#181d2a] border-pink-600/60 text-slate-100 shadow-xs'
                        : 'bg-[#141824] border-slate-700/60 text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <input
                        type="checkbox"
                        checked={Boolean(selectedIds[prop.testId])}
                        onChange={() => toggleSelect(prop.testId)}
                        className="rounded accent-pink-500"
                      />
                      <span className="font-mono font-bold text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {prop.method}
                      </span>
                      <span className="font-mono text-xs font-semibold truncate max-w-[260px]">
                        {prop.endpoint}
                      </span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-pink-950 text-pink-300 border border-pink-800/60">
                        {prop.vulnerabilityType.toUpperCase()}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500">ID: {prop.testId.slice(0, 6)}</span>
                  </label>
                ))}
              </div>
            )}

            {/* Unsupported Proposals Notice */}
            {unsupportedProposals.length > 0 && (
              <div className="mt-2 space-y-1">
                <span className="text-[10px] font-mono text-slate-500">
                  Unsupported Proposals (Deferred to Stage 6.4):
                </span>
                {unsupportedProposals.map((prop) => (
                  <div
                    key={prop.testId}
                    className="flex items-center justify-between p-2 rounded-lg border border-slate-800/80 bg-[#0e111a] text-slate-500 text-xs opacity-75"
                  >
                    <div className="flex items-center gap-2">
                      <input type="checkbox" disabled checked={false} className="cursor-not-allowed" />
                      <span className="font-mono text-[10px]">{prop.method} {prop.endpoint}</span>
                    </div>
                    <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-slate-800/80 text-amber-400 border border-amber-900/40">
                      NOT EXECUTED — Unsupported
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section 2: Sandbox Controls */}
          <div className="p-3 rounded-xl bg-[#161a28] border border-slate-700/60 space-y-2">
            <span className="font-semibold text-slate-200 flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-pink-500" />
              <span>Execution Safeguards & Budget</span>
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-[11px]">
              <div>
                <label className="block text-slate-400 font-mono mb-1">Execution Mode</label>
                <div className="p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-pink-300 font-semibold">
                  SPEC_DRIVEN
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Redirect Policy</label>
                <div className="p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-emerald-400 font-semibold">
                  Disabled (SSRF Safe)
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Max Requests (Budget)</label>
                <input
                  type="number"
                  min={1}
                  max={10}
                  value={maxRequests}
                  onChange={(e) => setMaxRequests(parseInt(e.target.value) || 10)}
                  className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 focus:outline-none focus:border-pink-500"
                />
              </div>
            </div>
          </div>

          {/* Section 3: Dynamic Identity Configuration */}
          {hasAuth && (
            <div className="p-3.5 rounded-xl bg-[#161a28] border border-pink-900/40 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-pink-300 flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-pink-400" />
                  <span>Authenticated Identity (Baseline Persona)</span>
                </span>
                <span className="text-[10px] font-mono text-slate-400">Required for Missing-Auth Testing</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Identity ID *</label>
                  <input
                    type="text"
                    value={authIdentityId}
                    onChange={(e) => setAuthIdentityId(e.target.value)}
                    placeholder="e.g. alice"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-pink-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-mono mb-1">Bearer Token / Credential *</label>
                  <input
                    type="password"
                    value={authToken}
                    onChange={(e) => setAuthToken(e.target.value)}
                    placeholder="e.g. test-bearer-token-alice-98765"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-pink-500"
                  />
                </div>
              </div>

              <label className="flex items-center gap-2 cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={authVerified}
                  onChange={(e) => setAuthVerified(e.target.checked)}
                  className="accent-pink-500 rounded"
                />
                <span className="text-[11px] text-slate-300 font-mono">
                  Confirm credentials are verified as valid (credentials_verified=true)
                </span>
              </label>
            </div>
          )}

          {hasBola && (
            <div className="p-3.5 rounded-xl bg-[#161a28] border border-blue-900/40 space-y-3">
              <span className="font-semibold text-blue-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-blue-400" />
                <span>BOLA Differential Personas (Owner vs Attacker)</span>
              </span>

              {/* Owner */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Owner Identity ID *</label>
                  <input
                    type="text"
                    value={ownerId}
                    onChange={(e) => setOwnerId(e.target.value)}
                    placeholder="e.g. owner_user"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Owner Token *</label>
                  <input
                    type="password"
                    value={ownerToken}
                    onChange={(e) => setOwnerToken(e.target.value)}
                    placeholder="Owner token"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Path Param ({ownerParamKey}) *</label>
                  <input
                    type="text"
                    value={ownerParamVal}
                    onChange={(e) => setOwnerParamVal(e.target.value)}
                    placeholder="e.g. 101"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Attacker */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-800">
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Attacker Identity ID *</label>
                  <input
                    type="text"
                    value={attackerId}
                    onChange={(e) => setAttackerId(e.target.value)}
                    placeholder="e.g. attacker_user"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Attacker Token (Different!) *</label>
                  <input
                    type="password"
                    value={attackerToken}
                    onChange={(e) => setAttackerToken(e.target.value)}
                    placeholder="Attacker token"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            </div>
          )}

          {hasBfla && (
            <div className="p-3.5 rounded-xl bg-[#161a28] border border-amber-900/40 space-y-3">
              <span className="font-semibold text-amber-300 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-amber-400" />
                <span>BFLA Differential Personas & Policy</span>
              </span>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Privileged Token (Admin) *</label>
                  <input
                    type="password"
                    value={privToken}
                    onChange={(e) => setPrivToken(e.target.value)}
                    placeholder="Admin token"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Lower-Privileged Token (User) *</label>
                  <input
                    type="password"
                    value={lowerToken}
                    onChange={(e) => setLowerToken(e.target.value)}
                    placeholder="User token"
                    className="w-full p-1.5 bg-[#0f121b] rounded border border-slate-700 font-mono text-slate-100 placeholder-slate-600"
                  />
                </div>
              </div>
            </div>
          )}

          <div className="p-2.5 rounded-lg bg-[#0e111a] border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
            <Info className="w-4 h-4 text-pink-500 shrink-0" />
            <span>
              Credentials are kept in-memory for this execution call only and are never saved to disk or localStorage.
            </span>
          </div>

          {/* Modal Actions */}
          <div className="pt-3 border-t border-slate-700/80 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={handleClose}
              disabled={isExecuting}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isExecuting || selectedProposalIds.length === 0}
              className="px-5 py-2 rounded-xl bg-gradient-to-r from-pink-500 via-rose-500 to-pink-500 hover:opacity-95 text-white text-xs font-semibold shadow-md shadow-pink-500/20 flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {isExecuting ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Probing Local Target...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Execute Selected Tests ({selectedProposalIds.length})</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
