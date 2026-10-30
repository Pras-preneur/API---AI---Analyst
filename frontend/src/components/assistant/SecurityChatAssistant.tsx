import React, { useState, useRef, useEffect } from 'react';
import {
  Sparkles,
  Send,
  Bot,
  User,
  Copy,
  Check,
  RefreshCw,
  Terminal,
  Shield,
  HelpCircle,
  Code2,
} from 'lucide-react';

interface ChatMessage {
  id: string;
  sender: 'ai' | 'user';
  text: string;
  codeSnippet?: string;
  timestamp: string;
}

interface SecurityChatAssistantProps {
  initialContext?: string | null;
}

const SUGGESTED_QUESTIONS = [
  'How do I implement an Open Policy Agent (OPA) check to prevent BOLA?',
  'Why does the ML model prioritize BOLA as P1 over BFLA?',
  'Provide safe verification curl commands without exploiting the endpoint.',
  'What are best practices for DTO schema validation against Mass Assignment?',
];

export const SecurityChatAssistant: React.FC<SecurityChatAssistantProps> = ({
  initialContext,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'm-1',
      sender: 'ai',
      text: initialContext
        ? `I am loaded with context on: "${initialContext}". How would you like to dissect the evidence, priority criteria, or defensive remediation strategy?`
        : 'Welcome to the API Security Analyst conversational intelligence engine. Ask questions regarding scanner verdicts, ML priority triage, OWASP API Top 10 vulnerabilities, or defensive remediation routines.',
      timestamp: 'Just now',
    },
  ]);

  const [inputPrompt, setInputPrompt] = useState<string>('');
  const [isTyping, setIsTyping] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const handleCopyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const generateAIResponse = (userQuestion: string): { text: string; codeSnippet?: string } => {
    const q = userQuestion.toLowerCase();

    if (q.includes('bola') || q.includes('idor') || q.includes('opa')) {
      return {
        text: 'Broken Object Level Authorization (BOLA) occurs when an endpoint consumes an object identifier without verifying that the requesting identity holds tenant ownership claims over that specific object. Here is the recommended defensive OPA Rego policy to enforce at your API gateway:',
        codeSnippet: `package httpapi.authz

default allow = false

# Validate object tenancy
allow {
    input.method == "GET"
    # Verify JWT subject matches requested user record ID
    input.identity.claims.user_id == input.path_params.id
}

# Allow tenant admin override if within tenant scope
allow {
    input.identity.claims.role == "tenant_admin"
    input.identity.claims.tenant_id == input.resource.tenant_id
}`,
      };
    } else if (q.includes('p1') || q.includes('priority') || q.includes('ml') || q.includes('model')) {
      return {
        text: 'The API Security Analyst ML classifier evaluates multiple feature vectors. When an endpoint has "internet_facing" exposure, "sensitive" data sensitivity, and "unauthenticated" access or high exploitability, the feature matrix produces high class probability for P1 (Critical Threat). Scanner verdicts remain authoritative facts, while ML recommendations provide triage velocity.',
      };
    } else if (q.includes('curl') || q.includes('test') || q.includes('verify') || q.includes('safe')) {
      return {
        text: 'Safe verification should only confirm defensive rejection without triggering state mutation or exfiltrating production records. Test with an orthogonal token and assert HTTP 403 Forbidden:',
        codeSnippet: `# Defensive Regression Verification
curl -s -o /dev/null -w "%{http_code}\\n" \\
  -X GET "https://api.gateway.internal/api/v2/users/test_user_b/financial-records" \\
  -H "Authorization: Bearer $TOKEN_FOR_USER_A"

# Expected Assertion Output:
# 403`,
      };
    } else if (q.includes('mass assignment') || q.includes('dto')) {
      return {
        text: 'To remediate Mass Assignment vulnerabilities, enforce strict Pydantic / DTO schemas with explicit allowlisted fields and forbid arbitrary client-supplied properties from binding directly to ORM models:',
        codeSnippet: `from pydantic import BaseModel, Field, ConfigDict

class UserProfileUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid") # Disallows unexpected keys like 'is_admin'

    display_name: str = Field(max_length=60)
    bio: str | None = None
    phone_number: str | None = None`,
      };
    }

    return {
      text: `Based on API security defense guidelines, this vector should be addressed by implementing defense-in-depth: input validation at the gateway, identity claims verification in middleware, and strict outbound projection filters.`,
    };
  };

  const handleSendMessage = (textToSend?: string) => {
    const text = textToSend || inputPrompt;
    if (!text.trim()) return;

    const userMsg: ChatMessage = {
      id: `u-${Date.now()}`,
      sender: 'user',
      text,
      timestamp: 'Just now',
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputPrompt('');
    setIsTyping(true);

    setTimeout(() => {
      const reply = generateAIResponse(text);
      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: reply.text,
        codeSnippet: reply.codeSnippet,
        timestamp: 'Just now',
      };
      setMessages((prev) => [...prev, aiMsg]);
      setIsTyping(false);
    }, 900);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-widest mb-1 font-bold">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>Nemotron AI Contextual Assistant</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-black text-white font-display">
            DEFENSIVE SECURITY COPILOT
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Interactively dissect findings, evaluate mitigation strategies, and generate defensive policies.
          </p>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          <span>Zero Attack Payloads • Defensive Only</span>
        </div>
      </div>

      {/* Main Chat Box Container */}
      <div className="glass-panel rounded-2xl border border-cyan-500/20 overflow-hidden flex flex-col h-[600px]">
        
        {/* Chat Messages Log */}
        <div className="flex-1 p-6 overflow-y-auto space-y-5">
          {messages.map((msg) => {
            const isAI = msg.sender === 'ai';
            return (
              <div
                key={msg.id}
                className={`flex gap-3.5 max-w-3xl ${isAI ? 'mr-auto' : 'ml-auto flex-row-reverse'}`}
              >
                {/* Avatar */}
                <div
                  className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${
                    isAI
                      ? 'bg-gradient-to-br from-cyan-500/30 to-blue-600/40 border border-cyan-400/40 text-cyan-300 shadow-cyber-cyan'
                      : 'bg-indigo-600 text-white'
                  }`}
                >
                  {isAI ? <Bot className="w-5 h-5" /> : <User className="w-5 h-5" />}
                </div>

                {/* Message Content Bubble */}
                <div
                  className={`p-4 rounded-2xl text-xs sm:text-sm leading-relaxed ${
                    isAI
                      ? 'bg-slate-900/90 border border-slate-700/80 text-slate-100'
                      : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-medium'
                  }`}
                >
                  <p>{msg.text}</p>

                  {/* Code Snippet if present */}
                  {msg.codeSnippet && (
                    <div className="mt-3 bg-slate-950 rounded-xl p-3 border border-slate-800 text-xs font-mono text-cyan-200 relative group">
                      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 text-[10px] text-slate-400 uppercase tracking-widest">
                        <span className="flex items-center gap-1.5">
                          <Code2 className="w-3 h-3 text-cyan-400" />
                          <span>Defensive Code Specification</span>
                        </span>
                        <button
                          onClick={() => handleCopyCode(msg.codeSnippet!, msg.id)}
                          className="hover:text-cyan-300 flex items-center gap-1"
                        >
                          {copiedId === msg.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="overflow-x-auto text-[11px] leading-snug">
                        {msg.codeSnippet}
                      </pre>
                    </div>
                  )}

                  <div className={`text-[10px] font-mono mt-2 ${isAI ? 'text-slate-400' : 'text-slate-800 font-semibold'}`}>
                    {msg.timestamp}
                  </div>
                </div>
              </div>
            );
          })}

          {/* Typing Indicator */}
          {isTyping && (
            <div className="flex gap-3 max-w-xl mr-auto items-center">
              <div className="w-9 h-9 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400">
                <Bot className="w-5 h-5 animate-pulse" />
              </div>
              <div className="px-4 py-3 rounded-2xl bg-slate-900 border border-slate-800 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" />
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce [animation-delay:0.2s]" />
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce [animation-delay:0.4s]" />
                <span className="text-xs font-mono text-slate-400 ml-2">Reasoning with security constraints...</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Suggested Quick Prompt Chips */}
        <div className="px-6 py-3 bg-slate-950/70 border-t border-slate-800/80 flex items-center gap-2 overflow-x-auto">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest shrink-0">
            Suggested:
          </span>
          {SUGGESTED_QUESTIONS.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(q)}
              className="text-[11px] font-mono px-3 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-cyan-400/20 whitespace-nowrap transition-colors"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-4 bg-slate-950 border-t border-slate-800">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-3"
          >
            <input
              type="text"
              value={inputPrompt}
              onChange={(e) => setInputPrompt(e.target.value)}
              placeholder="Ask the AI Security Copilot a technical finding question..."
              className="flex-1 px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-colors"
            />
            <button
              type="submit"
              disabled={!inputPrompt.trim() || isTyping}
              className="px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs uppercase tracking-wider disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shadow-cyber-cyan"
            >
              <span>Send</span>
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>

      </div>
    </div>
  );
};
