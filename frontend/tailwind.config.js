/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#030712',
          navy: '#060d1f',
          deep: '#0a1329',
          card: 'rgba(11, 20, 44, 0.7)',
          border: 'rgba(56, 189, 248, 0.16)',
          accent: '#00f0ff',
          neon: '#38bdf8',
          blue: '#1d4ed8',
          purple: '#6366f1',
          violet: '#8b5cf6',
        },
        pastel: {
          blue: "#a8d0e6",
          pink: "#f7c6c7",
          mint: "#b8e1dd",
          accent: "#ffb347",
          surface: "#ffffff",
          subtle: "#f3f4f6",
        },
        priority: {
          p1: '#f43f5e',
          p1Glow: 'rgba(244, 63, 94, 0.4)',
          p2: '#f59e0b',
          p2Glow: 'rgba(245, 158, 11, 0.4)',
          p3: '#06b6d4',
          p3Glow: 'rgba(6, 182, 212, 0.4)',
        },
      },
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'Inter', 'system-ui', 'sans-serif'],
        display: ['Outfit', 'Syne', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'soft-cyan': '0 0 12px rgba(56, 189, 248, 0.2)',
        'soft-glow': '0 0 25px -3px rgba(0, 240, 255, 0.35)',
        'cyber-cyan': '0 0 25px -3px rgba(0, 240, 255, 0.35)',
        'cyber-glow': '0 0 40px -5px rgba(56, 189, 248, 0.25)',
        'cyber-p1': '0 0 30px -4px rgba(244, 63, 94, 0.45)',
        'cyber-p2': '0 0 30px -4px rgba(245, 158, 11, 0.45)',
        'cyber-p3': '0 0 30px -4px rgba(6, 182, 212, 0.45)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.4)',
      },
      backgroundImage: {
        'radial-glow': 'radial-gradient(circle at 50% 50%, rgba(56, 189, 248, 0.15) 0%, rgba(3, 7, 18, 0) 70%)',
        'cyber-grid': 'linear-gradient(to right, rgba(56, 189, 248, 0.05) 1px, transparent 1px), linear-gradient(to bottom, rgba(56, 189, 248, 0.05) 1px, transparent 1px)',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'float-reverse': 'floatReverse 7s ease-in-out infinite',
        'spin-slow': 'spin 20s linear infinite',
        'radar-sweep': 'radarSweep 4s linear infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-12px)' },
        },
        floatReverse: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(12px)' },
        },
        radarSweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
      },
    },
  },
  plugins: [],
};
