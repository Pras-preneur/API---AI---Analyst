import React, { useState, useEffect } from 'react';
import { Mic, MicOff, Sparkles, Volume2 } from 'lucide-react';

interface SiriWaveAnimationProps {
  isLoading?: boolean;
  onQuickPrompt?: (prompt: string) => void;
  className?: string;
}

export const SiriWaveAnimation: React.FC<SiriWaveAnimationProps> = ({
  isLoading = false,
  onQuickPrompt,
  className = '',
}) => {
  const [isListening, setIsListening] = useState(false);
  const [waveAmplitudes, setWaveAmplitudes] = useState<number[]>([12, 24, 38, 52, 40, 26, 14]);

  // Dynamic wave animation when active (listening or loading)
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (isListening || isLoading) {
      interval = setInterval(() => {
        setWaveAmplitudes([
          Math.floor(Math.random() * 20) + 15,
          Math.floor(Math.random() * 40) + 25,
          Math.floor(Math.random() * 65) + 35,
          Math.floor(Math.random() * 85) + 45,
          Math.floor(Math.random() * 65) + 35,
          Math.floor(Math.random() * 40) + 25,
          Math.floor(Math.random() * 20) + 15,
        ]);
      }, 120);
    } else {
      // Gentle calm breathing state
      setWaveAmplitudes([10, 16, 26, 34, 26, 16, 10]);
    }
    return () => clearInterval(interval);
  }, [isListening, isLoading]);

  const toggleMic = () => {
    setIsListening((prev) => !prev);
  };

  return (
    <div className={`flex flex-col items-center justify-center p-6 text-center select-none ${className}`}>
      {/* Siri Ambient Glow Container */}
      <div className="relative flex items-center justify-center w-52 h-52 sm:w-60 sm:h-60">
        
        {/* Outer Radiant Pulsing Aura */}
        <div
          className={`absolute inset-0 rounded-full transition-all duration-700 blur-2xl opacity-60 ${
            isLoading
              ? 'bg-gradient-to-r from-pink-300 via-purple-300 to-cyan-300 animate-spin-slow scale-110'
              : isListening
              ? 'bg-gradient-to-tr from-cyan-300 via-pink-300 to-emerald-300 animate-pulse scale-105'
              : 'bg-gradient-to-tr from-blue-200 via-pink-200 to-teal-100 opacity-40 hover:opacity-60'
          }`}
        />

        {/* Secondary Inner Orb with Glassmorphism */}
        <div className="absolute w-40 h-40 sm:w-44 sm:h-44 rounded-full bg-white/70 backdrop-blur-xl border border-white/80 shadow-[0_10px_35px_-5px_rgba(168,208,230,0.45)] flex items-center justify-center transition-transform duration-500 hover:scale-[1.02]">
          
          {/* Animated Waveform Bars (Central Siri Waveform) */}
          <div className="flex items-center justify-center gap-1.5 h-24 px-4 z-10">
            {waveAmplitudes.map((height, idx) => {
              // Color spectrum across the bars: pastel blue -> lavender -> pink -> mint
              const barColors = [
                'bg-gradient-to-t from-sky-400 to-cyan-300',
                'bg-gradient-to-t from-blue-400 to-indigo-300',
                'bg-gradient-to-t from-indigo-400 to-purple-300',
                'bg-gradient-to-t from-pink-400 to-rose-300',
                'bg-gradient-to-t from-purple-400 to-pink-300',
                'bg-gradient-to-t from-teal-400 to-emerald-300',
                'bg-gradient-to-t from-cyan-400 to-teal-300',
              ];

              return (
                <div
                  key={idx}
                  style={{
                    height: `${height}px`,
                    transition: 'height 120ms cubic-bezier(0.4, 0, 0.2, 1)',
                  }}
                  className={`w-2 sm:w-2.5 rounded-full ${barColors[idx]} shadow-sm`}
                />
              );
            })}
          </div>

          {/* Interactive Microphone Button Overlay */}
          <button
            onClick={toggleMic}
            className={`absolute bottom-3 p-2 rounded-full transition-all z-20 shadow-md ${
              isListening
                ? 'bg-rose-500 text-white animate-bounce'
                : 'bg-white/90 hover:bg-white text-slate-600 hover:text-cyan-600 border border-slate-200/80 hover:shadow-cyan-100'
            }`}
            title={isListening ? 'Stop listening' : 'Start voice mode (Simulated Siri interaction)'}
          >
            {isListening ? <MicOff className="w-3.5 h-3.5" /> : <Mic className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Human-Psychology Status Label & Visual Hierarchy */}
      <div className="mt-3 space-y-1.5 max-w-md mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/80 border border-slate-200/80 shadow-sm text-xs font-medium text-slate-700">
          <span
            className={`w-2 h-2 rounded-full ${
              isLoading
                ? 'bg-purple-500 animate-ping'
                : isListening
                ? 'bg-rose-500 animate-pulse'
                : 'bg-emerald-400'
            }`}
          />
          <span className="font-sans">
            {isLoading
              ? 'Analyzing API Specification & Probe Vectors...'
              : isListening
              ? 'Listening to speech query (speak or type below)...'
              : 'Siri Copilot Active • Tap Mic or Ask Anything'}
          </span>
        </div>

        <p className="text-xs text-slate-500 leading-relaxed font-sans px-4">
          Human-in-the-loop security assistant. Propose safe probes, verify BOLA/IDOR risk, and get ML-prioritized findings.
        </p>
      </div>

      {/* Quick Interactive Pastel Action Pills */}
      {onQuickPrompt && (
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2 max-w-xl mx-auto">
          <button
            onClick={() => onQuickPrompt('Run full BOLA & IDOR vulnerability check on this specification')}
            className="px-3 py-1.5 rounded-full bg-blue-50/90 hover:bg-blue-100/90 text-blue-700 border border-blue-200/80 text-xs font-medium transition-all shadow-sm hover:scale-[1.02] flex items-center gap-1.5"
          >
            <Sparkles className="w-3 h-3 text-blue-500" />
            <span>Check BOLA / IDOR</span>
          </button>

          <button
            onClick={() => onQuickPrompt('Analyze authentication & token headers for broken authorization')}
            className="px-3 py-1.5 rounded-full bg-pink-50/90 hover:bg-pink-100/90 text-pink-700 border border-pink-200/80 text-xs font-medium transition-all shadow-sm hover:scale-[1.02] flex items-center gap-1.5"
          >
            <Volume2 className="w-3 h-3 text-pink-500" />
            <span>Auth & Token Analysis</span>
          </button>

          <button
            onClick={() => onQuickPrompt('Generate a comprehensive executive security assessment report')}
            className="px-3 py-1.5 rounded-full bg-emerald-50/90 hover:bg-emerald-100/90 text-emerald-700 border border-emerald-200/80 text-xs font-medium transition-all shadow-sm hover:scale-[1.02]"
          >
            <span>Generate Executive Report</span>
          </button>
        </div>
      )}
    </div>
  );
};
