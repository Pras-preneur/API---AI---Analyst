"""
Dark Obsidian Theme Patch for ZYNORA AI Components
Patches: ClaudeSidebar, ChatMainView, MessageComposer, ChatMessageItem
"""

import os

BASE = r'd:\Team - Zynora - Hackathon\API - Ai -  Analyst\frontend\src\components'

def patch_file(rel_path, replacements):
    full_path = os.path.join(BASE, rel_path)
    with open(full_path, 'r', encoding='utf-8') as f:
        content = f.read()
    count = 0
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            count += 1
            print(f'  [OK] {old[:70]}')
        else:
            print(f'  [!!] NOT FOUND: {old[:70]}')
    with open(full_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'  => {count}/{len(replacements)} replacements applied to {rel_path}\n')


# ─────────────────────────────────────────────────────────────────────────────
# 1. ClaudeSidebar.tsx
# ─────────────────────────────────────────────────────────────────────────────
patch_file('layout/ClaudeSidebar.tsx', [
    # Sidebar background
    (
        'bg-white/70 backdrop-blur-2xl border-r border-slate-200/70',
        'bg-[#0d1017]/95 backdrop-blur-2xl border-r border-slate-800/70'
    ),
    # Brand header border
    (
        'h-16 px-4 flex items-center justify-between border-b border-slate-200/60 shrink-0',
        'h-16 px-4 flex items-center justify-between border-b border-slate-800/60 shrink-0'
    ),
    # Brand logo bg
    (
        'w-8 h-8 rounded-xl bg-gradient-to-tr from-pink-400/25 via-purple-400/20 to-cyan-400/25 border border-white shadow-xs flex items-center justify-center',
        'w-8 h-8 rounded-xl bg-gradient-to-tr from-pink-500/30 via-purple-500/25 to-cyan-500/25 border border-slate-700/60 shadow-xs flex items-center justify-center'
    ),
    # Brand name text
    (
        'font-extrabold text-xs tracking-wide text-slate-800 font-heading',
        'font-extrabold text-xs tracking-wide text-slate-100 font-heading'
    ),
    # Brand subtitle
    (
        'text-[10px] font-mono text-slate-400',
        'text-[10px] font-mono text-slate-500'
    ),
    # Toggle button
    (
        'p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors ml-auto',
        'p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-800/70 transition-colors ml-auto'
    ),
    # Active nav item
    (
        "'bg-pink-50/80 text-pink-700 font-semibold border border-pink-200/60 shadow-xs'",
        "'bg-[#1c2230] text-pink-400 font-semibold border border-slate-700/60 shadow-xs'"
    ),
    # Inactive nav item
    (
        "'text-slate-600 hover:text-slate-900 hover:bg-slate-100/70'",
        "'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'"
    ),
    # Active nav icon
    (
        "'text-pink-600' : 'text-slate-400 group-hover:text-slate-600'",
        "'text-pink-400' : 'text-slate-500 group-hover:text-slate-300'"
    ),
    # Search history bar
    (
        'flex items-center gap-2 px-3 py-2 mx-3 mb-2 rounded-xl bg-slate-100/70 border border-slate-200/50',
        'flex items-center gap-2 px-3 py-2 mx-3 mb-2 rounded-xl bg-slate-800/50 border border-slate-700/50'
    ),
    # Search input
    (
        'w-full bg-transparent text-xs text-slate-700 placeholder-slate-400 focus:outline-none',
        'w-full bg-transparent text-xs text-slate-200 placeholder-slate-500 focus:outline-none'
    ),
    # Search icon
    (
        'w-3.5 h-3.5 text-slate-400 shrink-0',
        'w-3.5 h-3.5 text-slate-500 shrink-0'
    ),
    # "Previous sessions" label
    (
        'text-[10px] font-mono text-slate-400 tracking-wider uppercase px-4 py-1.5',
        'text-[10px] font-mono text-slate-600 tracking-wider uppercase px-4 py-1.5'
    ),
    # Active session button
    (
        "'w-full text-left px-3 py-2 rounded-xl text-xs flex items-center group relative transition-all bg-pink-50/80 border border-pink-200/50 text-pink-800 font-semibold shadow-xs'",
        "'w-full text-left px-3 py-2 rounded-xl text-xs flex items-center group relative transition-all bg-[#1c2230] border border-slate-700/60 text-slate-100 font-semibold shadow-xs'"
    ),
    # Inactive session button
    (
        "'w-full text-left px-3 py-2 rounded-xl text-xs flex items-center group relative transition-all text-slate-600 hover:bg-slate-100/70 hover:text-slate-900'",
        "'w-full text-left px-3 py-2 rounded-xl text-xs flex items-center group relative transition-all text-slate-400 hover:bg-slate-800/60 hover:text-slate-100'"
    ),
    # Active session icon
    (
        "'w-3.5 h-3.5 shrink-0 text-pink-500'",
        "'w-3.5 h-3.5 shrink-0 text-pink-400'"
    ),
    # Inactive session icon
    (
        "'w-3.5 h-3.5 shrink-0 text-slate-400'",
        "'w-3.5 h-3.5 shrink-0 text-slate-600'"
    ),
    # Session context menu button
    (
        'p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/70 opacity-0 group-hover:opacity-100 transition-all',
        'p-1 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-700/70 opacity-0 group-hover:opacity-100 transition-all'
    ),
    # Dropdown menu
    (
        'absolute right-0 top-8 w-44 bg-white/98 backdrop-blur-xl border border-slate-200 rounded-2xl shadow-xl p-1.5 z-50 space-y-0.5',
        'absolute right-0 top-8 w-44 bg-[#13161e]/98 backdrop-blur-xl border border-slate-700/70 rounded-2xl shadow-xl p-1.5 z-50 space-y-0.5'
    ),
    # Dropdown item
    (
        'w-full text-left px-3 py-2 rounded-xl text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100/70 transition-colors flex items-center gap-2',
        'w-full text-left px-3 py-2 rounded-xl text-xs text-slate-300 hover:text-slate-100 hover:bg-slate-800/70 transition-colors flex items-center gap-2'
    ),
    # Delete dropdown item
    (
        'w-full text-left px-3 py-2 rounded-xl text-xs text-rose-600 hover:text-rose-700 hover:bg-rose-50/70 transition-colors flex items-center gap-2',
        'w-full text-left px-3 py-2 rounded-xl text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-900/30 transition-colors flex items-center gap-2'
    ),
    # Rename input
    (
        'w-full bg-white/90 border border-pink-300 rounded-lg px-2 py-0.5 text-xs text-slate-800 focus:outline-none font-semibold',
        'w-full bg-[#0d1017]/90 border border-pink-500/50 rounded-lg px-2 py-0.5 text-xs text-slate-100 focus:outline-none font-semibold'
    ),
    # Sidebar footer divider
    (
        'p-3 border-t border-slate-200/60 shrink-0',
        'p-3 border-t border-slate-800/60 shrink-0'
    ),
    # User profile row
    (
        'flex items-center gap-2.5 px-2 py-2 rounded-xl hover:bg-slate-100/70 transition-colors cursor-pointer',
        'flex items-center gap-2.5 px-2 py-2 rounded-xl hover:bg-slate-800/60 transition-colors cursor-pointer'
    ),
    # User avatar bg
    (
        'w-7 h-7 rounded-full bg-gradient-to-tr from-pink-400 to-purple-500 flex items-center justify-center text-white text-xs font-bold shrink-0',
        'w-7 h-7 rounded-full bg-gradient-to-tr from-pink-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold shrink-0'
    ),
    # User name text
    (
        'text-xs font-semibold text-slate-800 leading-tight',
        'text-xs font-semibold text-slate-200 leading-tight'
    ),
    # User role text
    (
        'text-[10px] text-slate-400 font-mono',
        'text-[10px] text-slate-500 font-mono'
    ),
    # Settings gear icon
    (
        'w-4 h-4 text-slate-400 hover:text-slate-700 transition-colors',
        'w-4 h-4 text-slate-500 hover:text-slate-200 transition-colors'
    ),
])


# ─────────────────────────────────────────────────────────────────────────────
# 2. ChatMainView.tsx
# ─────────────────────────────────────────────────────────────────────────────
patch_file('chat/ChatMainView.tsx', [
    # Header bar bg
    (
        'h-13 sm:h-14 px-4 sm:px-6 flex items-center justify-between shrink-0 z-20 border-b border-slate-200/50 bg-white/60 backdrop-blur-md',
        'h-13 sm:h-14 px-4 sm:px-6 flex items-center justify-between shrink-0 z-20 border-b border-slate-800/60 bg-[#13161e]/80 backdrop-blur-md'
    ),
    # Mobile toggle button
    (
        'p-1.5 rounded-xl text-slate-500 hover:text-slate-800 hover:bg-slate-100 lg:hidden transition-colors',
        'p-1.5 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/70 lg:hidden transition-colors'
    ),
    # Active spec pill
    (
        'flex items-center gap-2 px-3 py-1 rounded-full bg-white/90 border border-slate-200/80 text-xs text-slate-800 shadow-xs',
        'flex items-center gap-2 px-3 py-1 rounded-full bg-[#181c26] border border-slate-700/80 text-xs text-slate-200 shadow-xs'
    ),
    # Spec pill endpoint count badge
    (
        'text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-pink-100 text-pink-700 font-bold shrink-0',
        'text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-pink-900/50 text-pink-300 font-bold shrink-0'
    ),
    # Inventory button
    (
        'hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-slate-600 hover:text-pink-600 hover:bg-white/80 border border-slate-200/60 transition-colors',
        'hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-slate-400 hover:text-pink-400 hover:bg-slate-800/60 border border-slate-700/50 transition-colors'
    ),
    # Backend status pill
    (
        'hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/70 border border-slate-200/60 text-[11px] font-mono text-slate-600',
        'hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#13161e]/80 border border-slate-700/50 text-[11px] font-mono text-slate-400'
    ),
    # New Chat button in header
    (
        'px-3 py-1 rounded-full bg-pink-50 hover:bg-pink-100/80 text-pink-700 border border-pink-200 text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors',
        'px-3 py-1 rounded-full bg-pink-900/40 hover:bg-pink-900/60 text-pink-300 border border-pink-800/50 text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors'
    ),
    # Connect Spec button
    (
        'px-3 py-1 rounded-full bg-white hover:bg-slate-50 text-slate-800 border border-slate-200/80 text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-all hover:border-pink-300 active:scale-95',
        'px-3 py-1 rounded-full bg-[#1a1e29] hover:bg-[#21263a] text-slate-200 border border-slate-700/70 text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-all hover:border-pink-500/40 active:scale-95'
    ),
    # Connect spec icon
    (
        'w-3.5 h-3.5 text-slate-500',
        'w-3.5 h-3.5 text-slate-400'
    ),
    # Welcome heading
    (
        'text-3xl sm:text-4xl md:text-[2.6rem] font-extrabold tracking-tight text-slate-900 font-heading leading-tight',
        'text-3xl sm:text-4xl md:text-[2.6rem] font-extrabold tracking-tight text-slate-100 font-heading leading-tight'
    ),
    # Welcome heading word "API Security" 
    (
        'text-slate-900 font-bold">API Security ',
        'text-slate-100 font-bold">API Security '
    ),
    # Welcome heading word "Voice Access"
    (
        'text-slate-900 font-bold">Voice Access',
        'text-slate-100 font-bold">Voice Access'
    ),
    # Welcome subtitle
    (
        'text-xs sm:text-sm text-slate-500 font-sans max-w-lg mx-auto leading-relaxed',
        'text-xs sm:text-sm text-slate-400 font-sans max-w-lg mx-auto leading-relaxed'
    ),
    # Processing indicator bubble
    (
        'flex items-center gap-2.5 bg-white/95 border border-pink-200 rounded-full px-4 py-2 shadow-xs text-xs text-pink-700 font-mono',
        'flex items-center gap-2.5 bg-[#161a24]/95 border border-pink-800/50 rounded-full px-4 py-2 shadow-xs text-xs text-pink-300 font-mono'
    ),
    # Footer composer bg
    (
        'shrink-0 w-full px-4 sm:px-6 md:px-8 py-3 bg-white/75 backdrop-blur-xl border-t border-slate-200/50 z-20',
        'shrink-0 w-full px-4 sm:px-6 md:px-8 py-3 bg-[#13161e]/85 backdrop-blur-xl border-t border-slate-800/60 z-20'
    ),
])


# ─────────────────────────────────────────────────────────────────────────────
# 3. MessageComposer.tsx
# ─────────────────────────────────────────────────────────────────────────────
patch_file('chat/MessageComposer.tsx', [
    # Suggestion chips
    (
        'px-3.5 py-1.5 rounded-full bg-white/90 hover:bg-white text-slate-700 hover:text-pink-600 border border-slate-200/90 hover:border-pink-300 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0',
        'px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-pink-400 border border-slate-700/80 hover:border-pink-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0'
    ),
    (
        'px-3.5 py-1.5 rounded-full bg-white/90 hover:bg-white text-slate-700 hover:text-purple-600 border border-slate-200/90 hover:border-purple-300 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0',
        'px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-purple-400 border border-slate-700/80 hover:border-purple-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0'
    ),
    (
        'px-3.5 py-1.5 rounded-full bg-white/90 hover:bg-white text-slate-700 hover:text-cyan-600 border border-slate-200/90 hover:border-cyan-300 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0',
        'px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-cyan-400 border border-slate-700/80 hover:border-cyan-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0'
    ),
    (
        'px-3.5 py-1.5 rounded-full bg-white/90 hover:bg-white text-slate-700 hover:text-pink-600 border border-slate-200/90 hover:border-pink-300 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0',
        'px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-pink-400 border border-slate-700/80 hover:border-pink-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0'
    ),
    # More button
    (
        'w-7 h-7 rounded-full bg-white/90 hover:bg-white text-slate-600 border border-slate-200/90 flex items-center justify-center text-xs font-bold transition-all shadow-xs hover:border-pink-300',
        'w-7 h-7 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-400 border border-slate-700/80 flex items-center justify-center text-xs font-bold transition-all shadow-xs hover:border-pink-500/40'
    ),
    # More dropdown menu
    (
        'absolute bottom-9 right-0 w-52 bg-white/95 backdrop-blur-xl border border-slate-200 rounded-2xl shadow-xl p-1.5 z-50 text-xs space-y-1',
        'absolute bottom-9 right-0 w-52 bg-[#13161e]/98 backdrop-blur-xl border border-slate-700/70 rounded-2xl shadow-xl p-1.5 z-50 text-xs space-y-1'
    ),
    # More dropdown item (assessment)
    (
        'w-full text-left px-3 py-2 rounded-xl hover:bg-pink-50 hover:text-pink-700 font-medium transition-colors flex items-center gap-2',
        'w-full text-left px-3 py-2 rounded-xl hover:bg-pink-900/30 hover:text-pink-300 text-slate-300 font-medium transition-colors flex items-center gap-2'
    ),
    # Input capsule outer gradient
    (
        'p-[1.5px] rounded-[28px] bg-gradient-to-r from-amber-200/60 via-pink-300/70 to-cyan-200/60 shadow-[0_12px_45px_rgba(244,114,182,0.14)] transition-all focus-within:shadow-[0_12px_45px_rgba(244,114,182,0.24)] focus-within:ring-2 focus-within:ring-pink-300/40',
        'p-[1.5px] rounded-[28px] bg-gradient-to-r from-sky-500/30 via-pink-500/30 to-purple-500/30 shadow-[0_12px_45px_rgba(236,72,153,0.12)] transition-all focus-within:shadow-[0_12px_45px_rgba(236,72,153,0.22)] focus-within:ring-2 focus-within:ring-pink-500/30'
    ),
    # Input capsule inner
    (
        'bg-white/95 backdrop-blur-2xl rounded-[26.5px] px-5 pt-3.5 pb-2.5 space-y-2 border border-white/80',
        'bg-[#141720]/95 backdrop-blur-2xl rounded-[26.5px] px-5 pt-3.5 pb-2.5 space-y-2 border border-slate-800/80'
    ),
    # Textarea
    (
        'w-full bg-transparent text-sm text-slate-800 placeholder-slate-400 focus:outline-none resize-none min-h-[42px] max-h-[130px] leading-relaxed font-sans',
        'w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none resize-none min-h-[42px] max-h-[130px] leading-relaxed font-sans'
    ),
    # Bottom actions divider
    (
        'flex items-center justify-between pt-1 border-t border-slate-100/80',
        'flex items-center justify-between pt-1 border-t border-slate-800/60'
    ),
    # Attach button
    (
        'px-2.5 py-1 rounded-full text-slate-500 hover:text-slate-800 hover:bg-slate-100/80 text-xs flex items-center gap-1.5 transition-colors',
        'px-2.5 py-1 rounded-full text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 text-xs flex items-center gap-1.5 transition-colors'
    ),
    # Paperclip icon
    (
        'w-3.5 h-3.5 text-slate-500',
        'w-3.5 h-3.5 text-slate-400'
    ),
    # Deep Think active
    (
        "'bg-purple-100/80 text-purple-800 border border-purple-200 font-semibold shadow-xs'",
        "'bg-purple-900/50 text-purple-300 border border-purple-700/50 font-semibold shadow-xs'"
    ),
    # Deep Think inactive
    (
        "'text-slate-500 hover:bg-slate-100/80'",
        "'text-slate-400 hover:bg-slate-800/60'"
    ),
    # Deep Think icon active fill
    (
        "deepThinkActive ? 'text-purple-600 fill-purple-300' : 'text-slate-400'",
        "deepThinkActive ? 'text-purple-400 fill-purple-700' : 'text-slate-500'"
    ),
    # Voice active
    (
        "'bg-rose-500 text-white font-semibold animate-pulse shadow-xs'",
        "'bg-rose-600 text-white font-semibold animate-pulse shadow-xs'"
    ),
    # Voice inactive
    (
        "'text-slate-600 hover:text-slate-900 hover:bg-slate-100/80'",
        "'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'"
    ),
    # Mic icon
    (
        'w-3.5 h-3.5 text-slate-500" />',
        'w-3.5 h-3.5 text-slate-400" />'
    ),
])


# ─────────────────────────────────────────────────────────────────────────────
# 4. ChatMessageItem.tsx
# ─────────────────────────────────────────────────────────────────────────────
patch_file('chat/ChatMessageItem.tsx', [
    # Timestamp muted
    (
        'text-[10px] text-slate-400 font-mono mt-0.5 pr-1',
        'text-[10px] text-slate-500 font-mono mt-0.5 pr-1'
    ),
    # Assistant glass card
    (
        'flex-1 space-y-2 min-w-0',
        'flex-1 space-y-2 min-w-0'  # no change needed here, just the card below
    ),
])

# ChatMessageItem needs special handling for the message cards
path = os.path.join(BASE, 'chat/ChatMessageItem.tsx')
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace assistant message card classes  
content = content.replace(
    'rounded-2xl rounded-tl-xs px-4 py-3 shadow-xs border text-sm font-sans bg-white/90 border-slate-200/80 text-slate-800',
    'rounded-2xl rounded-tl-xs px-4 py-3 shadow-xs border text-sm font-sans bg-[#161a24]/90 border-slate-800/80 text-slate-200'
)
# Broader class replacement for assistant card if the above doesn't match exactly
if 'bg-white/90 border-slate-200/80 text-slate-800' in content:
    content = content.replace(
        'bg-white/90 border-slate-200/80 text-slate-800',
        'bg-[#161a24]/90 border-slate-800/80 text-slate-200'
    )
    print('  [OK] Assistant message card bg')

# AI Security Analyst label
content = content.replace(
    'text-xs font-semibold text-slate-800',
    'text-xs font-semibold text-slate-200'
)
# Online dot label text
content = content.replace(
    '"text-[10px] font-mono text-slate-400 ml-1"',
    '"text-[10px] font-mono text-slate-500 ml-1"'
)
# Timestamp in assistant message
content = content.replace(
    'text-[10px] text-slate-400 font-mono',
    'text-[10px] text-slate-500 font-mono'
)
# Copy button
content = content.replace(
    'p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors',
    'p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-800/70 transition-colors'
)
# Proposed test cards
content = content.replace(
    'p-3 rounded-xl bg-slate-50/80 border border-slate-200/70',
    'p-3 rounded-xl bg-[#181d28]/80 border border-slate-800/60'
)
content = content.replace(
    'p-3 rounded-xl bg-white/80 border border-slate-200/70',
    'p-3 rounded-xl bg-[#181d28]/80 border border-slate-800/60'
)
# Proposed test card header text
content = content.replace(
    'text-xs font-mono font-semibold text-slate-700 truncate',
    'text-xs font-mono font-semibold text-slate-300 truncate'
)
# Proposed test card description
content = content.replace(
    'text-xs text-slate-500 font-sans mt-1 leading-relaxed',
    'text-xs text-slate-400 font-sans mt-1 leading-relaxed'
)
# Proposed test footer
content = content.replace(
    'flex items-center justify-between pt-2 border-t border-slate-100/80',
    'flex items-center justify-between pt-2 border-t border-slate-700/40'
)
# Expand/collapse button
content = content.replace(
    'text-[10px] text-slate-500 hover:text-slate-700 flex items-center gap-0.5 transition-colors font-mono',
    'text-[10px] text-slate-500 hover:text-slate-300 flex items-center gap-0.5 transition-colors font-mono'
)
# Expanded detail bg
content = content.replace(
    'mt-2 p-2.5 rounded-lg bg-slate-900/80 border border-slate-700/50 font-mono text-[10px] text-emerald-300 overflow-x-auto',
    'mt-2 p-2.5 rounded-lg bg-[#0a0c12]/90 border border-slate-700/50 font-mono text-[10px] text-emerald-400 overflow-x-auto'
)
# Report option cards
content = content.replace(
    'group flex items-start gap-3 p-3.5 rounded-xl bg-white/80 border border-slate-200/70 hover:bg-white hover:border-pink-200 shadow-xs hover:shadow-sm transition-all cursor-pointer',
    'group flex items-start gap-3 p-3.5 rounded-xl bg-[#181d28] border border-slate-700/70 hover:bg-[#202736] hover:border-pink-500/30 shadow-xs hover:shadow-sm transition-all cursor-pointer'
)
# Report option title
content = content.replace(
    'text-xs font-semibold text-slate-800 group-hover:text-pink-700',
    'text-xs font-semibold text-slate-200 group-hover:text-pink-400'
)
# Report option description
content = content.replace(
    'text-[10px] text-slate-500 font-sans mt-0.5 leading-relaxed',
    'text-[10px] text-slate-400 font-sans mt-0.5 leading-relaxed'
)
# Status: pending badge
content = content.replace(
    '"px-2 py-0.5 rounded-full text-[10px] font-semibold font-mono bg-amber-100 text-amber-700"',
    '"px-2 py-0.5 rounded-full text-[10px] font-semibold font-mono bg-amber-900/40 text-amber-300"'
)
# Status: approved badge  
content = content.replace(
    '"px-2 py-0.5 rounded-full text-[10px] font-semibold font-mono bg-emerald-100 text-emerald-700"',
    '"px-2 py-0.5 rounded-full text-[10px] font-semibold font-mono bg-emerald-900/40 text-emerald-300"'
)
# Status: rejected badge
content = content.replace(
    '"px-2 py-0.5 rounded-full text-[10px] font-semibold font-mono bg-rose-100 text-rose-700"',
    '"px-2 py-0.5 rounded-full text-[10px] font-semibold font-mono bg-rose-900/40 text-rose-300"'
)
# Finding card severity badges  
content = content.replace(
    'p-3 rounded-xl border bg-rose-50/80 border-rose-200/70',
    'p-3 rounded-xl border bg-rose-900/20 border-rose-800/40'
)
content = content.replace(
    'p-3 rounded-xl border bg-amber-50/80 border-amber-200/70',
    'p-3 rounded-xl border bg-amber-900/20 border-amber-800/40'
)
content = content.replace(
    'p-3 rounded-xl border bg-slate-50/80 border-slate-200/70',
    'p-3 rounded-xl border bg-slate-900/30 border-slate-700/50'
)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print(f'  => ChatMessageItem.tsx patched\n')


print('\n=== ALL PATCHES COMPLETE ===')
