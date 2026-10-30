import React, { useState, useRef, useEffect } from 'react';
import {
  Paperclip,
  Lightbulb,
  Mic,
  MicOff,
  Send,
  Sparkles,
  Shield,
  Layers,
  FileDown,
  ChevronDown,
} from 'lucide-react';

interface MessageComposerProps {
  onSendMessage: (text: string) => void;
  onOpenUpload: () => void;
  onOpenInventory?: () => void;
  onOpenReport?: () => void;
  onVoiceStateChange?: (active: boolean) => void;
  isLoading: boolean;
  disabled?: boolean;
  showChips?: boolean;
}

export const MessageComposer: React.FC<MessageComposerProps> = ({
  onSendMessage,
  onOpenUpload,
  onOpenInventory,
  onOpenReport,
  onVoiceStateChange,
  isLoading,
  disabled = false,
  showChips = true,
}) => {
  const [inputText, setInputText] = useState('');
  const [deepThinkActive, setDeepThinkActive] = useState(true);
  const [isVoiceActive, setIsVoiceActive] = useState(false);
  const [showMoreMenu, setShowMoreMenu] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 130)}px`;
    }
  }, [inputText]);

  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!inputText.trim() || isLoading || disabled) return;
    onSendMessage(inputText.trim());
    setInputText('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const toggleVoice = () => {
    const nextState = !isVoiceActive;
    setIsVoiceActive(nextState);
    onVoiceStateChange?.(nextState);

    if (nextState) {
      // Simulate real conversational voice recognition prompt
      const simulatedPrompts = [
        'Analyze authorization vulnerabilities across customer endpoints',
        'Check for broken function level authorization in admin paths',
        'Verify tenant isolation and BOLA risks on banking APIs',
        'Generate complete security assessment report',
      ];
      const randomPrompt =
        simulatedPrompts[Math.floor(Math.random() * simulatedPrompts.length)];
      setTimeout(() => {
        setInputText(randomPrompt);
        setIsVoiceActive(false);
        onVoiceStateChange?.(false);
      }, 2200);
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto select-none">
      
      {/* Optional Suggestion Quick Action Chips */}
      {showChips && (
        <div className="flex items-center justify-center gap-2 mb-3.5 overflow-x-auto no-scrollbar py-1 px-1">
          <button
            onClick={() => onSendMessage('Run comprehensive security audit scan on all parsed endpoints')}
            className="px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-pink-400 border border-slate-700/80 hover:border-pink-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0"
          >
            <Sparkles className="w-3.5 h-3.5 text-pink-500" />
            <span>Security Audit</span>
          </button>

          <button
            onClick={() => onSendMessage('Identify highest risk P1 vulnerabilities using ML classifier')}
            className="px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-purple-400 border border-slate-700/80 hover:border-purple-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0"
          >
            <Shield className="w-3.5 h-3.5 text-purple-500" />
            <span>High Risk P1</span>
          </button>

          <button
            onClick={() => (onOpenInventory ? onOpenInventory() : onSendMessage('Show parsed endpoints inventory'))}
            className="px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-cyan-400 border border-slate-700/80 hover:border-cyan-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0"
          >
            <Layers className="w-3.5 h-3.5 text-cyan-500" />
            <span>API Inventory</span>
          </button>

          <button
            onClick={() => onSendMessage('Formulate human-in-the-loop BOLA probes for user account endpoints')}
            className="px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-pink-400 border border-slate-700/80 hover:border-pink-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0"
          >
            <span>BOLA Probes</span>
          </button>

          <div className="relative">
            <button
              onClick={() => setShowMoreMenu((prev) => !prev)}
              className="w-7 h-7 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-400 border border-slate-700/80 flex items-center justify-center text-xs font-bold transition-all shadow-xs hover:border-pink-500/40"
              title="More Options"
            >
              ···
            </button>

            {showMoreMenu && (
              <div className="absolute bottom-9 right-0 w-52 bg-[#13161e]/98 backdrop-blur-xl border border-slate-700/70 rounded-2xl shadow-xl p-1.5 z-50 text-xs space-y-1">
                <button
                  onClick={() => {
                    onOpenReport?.();
                    setShowMoreMenu(false);
                  }}
                  className="w-full text-left px-3 py-2 rounded-xl hover:bg-pink-900/30 hover:text-pink-300 text-slate-300 font-medium transition-colors flex items-center gap-2"
                >
                  <FileDown className="w-3.5 h-3.5 text-pink-500" />
                  <span>Assessment Report</span>
                </button>
                <button
                  onClick={() => {
                    onSendMessage('Scan for Mass Assignment and excessive data exposure parameters');
                    setShowMoreMenu(false);
                  }}
                  className="w-full text-left px-3 py-2 rounded-xl hover:bg-pink-900/30 hover:text-pink-300 text-slate-300 font-medium transition-colors flex items-center gap-2"
                >
                  <Shield className="w-3.5 h-3.5 text-purple-500" />
                  <span>Mass Assignment Scan</span>
                </button>
                <button
                  onClick={() => {
                    onOpenUpload();
                    setShowMoreMenu(false);
                  }}
                  className="w-full text-left px-3 py-2 rounded-xl hover:bg-pink-900/30 hover:text-pink-300 text-slate-300 font-medium transition-colors flex items-center gap-2"
                >
                  <Paperclip className="w-3.5 h-3.5 text-cyan-500" />
                  <span>Upload OpenAPI Spec</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Floating Luminous Input Capsule with Soft Iridescent Rim */}
      <div className="p-[1.5px] rounded-[28px] bg-gradient-to-r from-sky-500/30 via-pink-500/30 to-purple-500/30 shadow-[0_12px_45px_rgba(236,72,153,0.12)] transition-all focus-within:shadow-[0_12px_45px_rgba(236,72,153,0.22)] focus-within:ring-2 focus-within:ring-pink-500/30">
        <div className="bg-[#141720]/95 backdrop-blur-2xl rounded-[26.5px] px-5 pt-3.5 pb-2.5 space-y-2 border border-slate-800/80">
          
          {/* Main Textarea */}
          <textarea
            ref={textareaRef}
            rows={1}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={isVoiceActive ? 'Listening... Speak your API command...' : 'Ask me anything about your API specs, vulnerabilities, or tests...'}
            disabled={disabled || isLoading}
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none resize-none min-h-[42px] max-h-[130px] leading-relaxed font-sans"
          />

          {/* Bottom Actions Bar */}
          <div className="flex items-center justify-between pt-1 border-t border-slate-800/60">
            {/* Left Controls: Attach Spec & Deep Think */}
            <div className="flex items-center gap-1.5 sm:gap-2">
              <button
                type="button"
                onClick={onOpenUpload}
                className="px-2.5 py-1 rounded-full text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 text-xs flex items-center gap-1.5 transition-colors"
                title="Attach OpenAPI JSON/YAML Specification"
              >
                <Paperclip className="w-3.5 h-3.5 text-slate-400" />
                <span className="hidden sm:inline font-medium">Attach</span>
              </button>

              <button
                type="button"
                onClick={() => setDeepThinkActive(!deepThinkActive)}
                className={`px-3 py-1 rounded-full text-xs flex items-center gap-1.5 transition-all ${
                  deepThinkActive
                    ? 'bg-purple-900/50 text-purple-300 border border-purple-700/50 font-semibold shadow-xs'
                    : 'text-slate-400 hover:bg-slate-800/60'
                }`}
                title="Toggle SLM Deep Reasoning & ML Classifier"
              >
                <Lightbulb className={`w-3.5 h-3.5 ${deepThinkActive ? 'text-purple-400 fill-purple-700' : 'text-slate-500'}`} />
                <span className="font-medium">Deep Think</span>
              </button>
            </div>

            {/* Right Controls: Voice Toggle & Send Button */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={toggleVoice}
                className={`px-3 py-1 rounded-full text-xs flex items-center gap-1.5 transition-all ${
                  isVoiceActive
                    ? 'bg-rose-600 text-white font-semibold animate-pulse shadow-xs'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                }`}
                title={isVoiceActive ? 'Listening... click to stop' : 'Activate Voice Access'}
              >
                {isVoiceActive ? <MicOff className="w-3.5 h-3.5" /> : <Mic className="w-3.5 h-3.5 text-slate-400" />}
                <span className="hidden sm:inline font-medium">{isVoiceActive ? 'Speaking...' : 'Voice'}</span>
              </button>

              <button
                type="button"
                onClick={() => handleSubmit()}
                disabled={!inputText.trim() || isLoading || disabled}
                className="px-4 py-1.5 rounded-full bg-gradient-to-r from-pink-500 via-rose-500 to-pink-500 hover:opacity-95 disabled:opacity-40 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-pink-500/25 transition-all active:scale-95"
                title="Send instruction to AI Assistant"
              >
                <Send className="w-3 h-3 fill-current" />
                <span>Send</span>
              </button>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
