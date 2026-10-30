import re

path = r'd:\Team - Zynora - Hackathon\API - Ai -  Analyst\frontend\src\App.tsx'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    # Outer wrapper background
    (
        'bg-gradient-to-br from-[#fbf2f8] via-[#f7f2fa] to-[#eaf2fb]',
        'bg-gradient-to-br from-[#05060a] via-[#0b0e15] to-[#13161e]'
    ),
    # Ambient blobs
    (
        'bg-pink-200/40 blur-3xl pointer-events-none',
        'bg-sky-900/20 blur-3xl pointer-events-none'
    ),
    (
        'bg-cyan-200/35 blur-3xl pointer-events-none',
        'bg-purple-900/20 blur-3xl pointer-events-none'
    ),
    (
        'bg-purple-200/30 blur-3xl pointer-events-none',
        'bg-pink-900/15 blur-3xl pointer-events-none'
    ),
    # Main card
    (
        "bg-white/75 backdrop-blur-3xl border border-white/80 shadow-[0_25px_80px_rgba(180,165,205,0.28)] flex overflow-hidden ring-1 ring-white/70",
        "bg-[#11141c]/90 backdrop-blur-3xl border border-slate-800/80 shadow-[0_25px_80px_rgba(0,0,0,0.6)] flex overflow-hidden ring-1 ring-white/[0.06]"
    ),
    # Inventory heading border
    (
        'flex items-center justify-between pb-4 border-b border-slate-200">',
        'flex items-center justify-between pb-4 border-b border-slate-700/60">'
    ),
    # Inventory heading text
    (
        'text-2xl font-bold text-slate-800 font-heading">\n                    Parsed API Inventory',
        'text-2xl font-bold text-slate-100 font-heading">\n                    Parsed API Inventory'
    ),
    # Inventory subtext
    (
        'text-xs text-slate-500 font-sans mt-0.5">\n                    {activeSpec?.title}',
        'text-xs text-slate-400 font-sans mt-0.5">\n                    {activeSpec?.title}'
    ),
    # Inventory upload button
    (
        'px-4 py-2 rounded-full bg-white hover:bg-slate-50 text-slate-800 border border-slate-200 text-xs font-semibold flex items-center gap-2 shadow-xs transition-colors',
        'px-4 py-2 rounded-full bg-[#1a1e29] hover:bg-[#21263a] text-slate-200 border border-slate-700/70 text-xs font-semibold flex items-center gap-2 shadow-xs transition-colors'
    ),
    # Upload icon color (in inventory)
    (
        'className="w-3.5 h-3.5 text-pink-500" />\n                  <span>Upload Specification</span>',
        'className="w-3.5 h-3.5 text-pink-400" />\n                  <span>Upload Specification</span>'
    ),
    # Endpoint card bg
    (
        'p-4 rounded-2xl bg-white/80 border border-slate-200/80 shadow-xs space-y-2 hover:border-pink-300 transition-all',
        'p-4 rounded-2xl bg-[#161a24]/80 border border-slate-700/60 shadow-xs space-y-2 hover:border-pink-500/40 transition-all'
    ),
    # Method badges
    (
        "'bg-blue-100 text-blue-700'",
        "'bg-blue-900/50 text-blue-300'"
    ),
    (
        "'bg-emerald-100 text-emerald-700'",
        "'bg-emerald-900/50 text-emerald-300'"
    ),
    (
        "'bg-amber-100 text-amber-700'",
        "'bg-amber-900/50 text-amber-300'"
    ),
    # Endpoint path text
    (
        'font-semibold text-slate-800 truncate max-w-[220px]',
        'font-semibold text-slate-200 truncate max-w-[220px]'
    ),
    # Auth badge
    (
        'text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-600',
        'text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800/80 text-slate-400'
    ),
    # Endpoint summary text
    (
        'text-xs text-slate-600 font-sans">{ep.summary}',
        'text-xs text-slate-400 font-sans">{ep.summary}'
    ),
    # Endpoint card divider
    (
        'flex items-center justify-between pt-2 border-t border-slate-100',
        'flex items-center justify-between pt-2 border-t border-slate-700/40'
    ),
    # Risk badge
    (
        'text-[10px] font-mono text-pink-700 bg-pink-50 px-2 py-0.5 rounded-full',
        'text-[10px] font-mono text-pink-400 bg-pink-900/30 px-2 py-0.5 rounded-full'
    ),
    # Scan vector button
    (
        'text-xs text-pink-600 hover:text-pink-700 font-medium',
        'text-xs text-pink-400 hover:text-pink-300 font-medium'
    ),
    # Reports section border
    (
        'flex items-center justify-between pb-4 border-b border-slate-200">\n                <div>\n                  <h1 className="text-2xl font-bold text-slate-800 font-heading">\n                    Security Assessment Reports',
        'flex items-center justify-between pb-4 border-b border-slate-700/60">\n                <div>\n                  <h1 className="text-2xl font-bold text-slate-100 font-heading">\n                    Security Assessment Reports'
    ),
    # Reports subtext
    (
        'text-xs text-slate-500 font-sans mt-0.5">\n                    Exportable audit reports',
        'text-xs text-slate-400 font-sans mt-0.5">\n                    Exportable audit reports'
    ),
    # Reports white card
    (
        'p-8 rounded-2xl bg-white/80 border border-slate-200/80 text-center space-y-3',
        'p-8 rounded-2xl bg-[#161a24]/80 border border-slate-700/60 text-center space-y-3'
    ),
    # Reports heading inside card
    (
        'text-sm font-bold text-slate-800 font-heading">\n                  Executive Defense Report Ready',
        'text-sm font-bold text-slate-100 font-heading">\n                  Executive Defense Report Ready'
    ),
    # Reports description text
    (
        'text-xs text-slate-500 max-w-md mx-auto',
        'text-xs text-slate-400 max-w-md mx-auto'
    ),
    # Open report modal button
    (
        'px-5 py-2 rounded-full bg-slate-900 text-white text-xs font-semibold hover:bg-slate-800 transition-colors',
        'px-5 py-2 rounded-full bg-[#1a1e29] text-slate-100 text-xs font-semibold hover:bg-[#21263a] border border-slate-700/70 transition-colors'
    ),
]

for old, new in replacements:
    if old in content:
        content = content.replace(old, new)
        print(f'  Replaced: {old[:60]}...')
    else:
        print(f'  NOT FOUND: {old[:60]}...')

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print('Done App.tsx dark theme patch')
