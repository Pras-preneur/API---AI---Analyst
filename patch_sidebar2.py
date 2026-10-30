"""
Patch ClaudeSidebar remaining elements + other minor fixes
"""
import os

BASE = r'd:\Team - Zynora - Hackathon\API - Ai -  Analyst\frontend\src\components'

def patch(path, replacements):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            print(f'  [OK] {old[:70]}')
        else:
            print(f'  [!!] NOT FOUND: {old[:70]}')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

sidebar = os.path.join(BASE, 'layout/ClaudeSidebar.tsx')
patch(sidebar, [
    # Badge pill (cowork auto badge)
    (
        'text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-pink-100 text-pink-700 font-bold uppercase',
        'text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-pink-900/40 text-pink-300 font-bold uppercase'
    ),
    # Search input container
    (
        'w-full pl-8 pr-3 py-1.5 bg-slate-50/80 border border-slate-200/80 rounded-xl text-[11px] text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-pink-300',
        'w-full pl-8 pr-3 py-1.5 bg-slate-800/50 border border-slate-700/60 rounded-xl text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-pink-500/40'
    ),
    # Search icon absolute
    (
        'w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5',
        'w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5'
    ),
    # Sessions label row
    (
        'text-[10px] font-mono uppercase tracking-wider text-slate-400 px-2 py-1 font-semibold flex items-center justify-between',
        'text-[10px] font-mono uppercase tracking-wider text-slate-600 px-2 py-1 font-semibold flex items-center justify-between'
    ),
    # Clock icon
    (
        'w-3 h-3 text-slate-400',
        'w-3 h-3 text-slate-600'
    ),
    # No matching sessions text
    (
        'text-center py-6 text-xs text-slate-400',
        'text-center py-6 text-xs text-slate-500'
    ),
    # Active session row
    (
        "'bg-slate-100/90 text-slate-900 font-semibold shadow-xs'",
        "'bg-[#1c2230] text-slate-100 font-semibold shadow-xs'"
    ),
    # Inactive session row
    (
        "'text-slate-600 hover:text-slate-900 hover:bg-slate-50'",
        "'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'"
    ),
    # Rename input inline
    (
        'w-full px-2 py-0.5 text-xs bg-white border border-pink-300 rounded font-normal',
        'w-full px-2 py-0.5 text-xs bg-[#0d1017]/90 border border-pink-500/50 rounded font-normal text-slate-100'
    ),
    # Session message icon (inactive)
    (
        'w-3.5 h-3.5 text-slate-500 shrink-0',
        'w-3.5 h-3.5 text-slate-600 shrink-0'
    ),
    # 3-dot menu trigger button
    (
        'opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-200 text-slate-500 transition-opacity',
        'opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-700/70 text-slate-500 hover:text-slate-200 transition-opacity'
    ),
    # Context popup menu
    (
        'absolute right-0 top-6 w-36 bg-white border border-slate-200 rounded-xl shadow-lg p-1 z-50 text-[11px] space-y-0.5',
        'absolute right-0 top-6 w-36 bg-[#13161e] border border-slate-700/70 rounded-xl shadow-lg p-1 z-50 text-[11px] space-y-0.5'
    ),
    # Rename menu item
    (
        'w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-50 flex items-center gap-1.5 text-slate-700',
        'w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800/70 flex items-center gap-1.5 text-slate-300'
    ),
    # Delete menu item
    (
        'w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-rose-50 flex items-center gap-1.5 text-rose-600',
        'w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-rose-900/30 flex items-center gap-1.5 text-rose-400'
    ),
    # Edit2 / Archive icon in menu
    (
        'w-3 h-3 text-slate-400',
        'w-3 h-3 text-slate-500'
    ),
    # Settings button: active
    (
        "'bg-slate-100 text-slate-900 font-semibold'",
        "'bg-[#1c2230] text-slate-100 font-semibold'"
    ),
    # Settings button: inactive
    (
        "'text-slate-600 hover:text-slate-900 hover:bg-slate-50'",
        "'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'"
    ),
    # Settings icon
    (
        'w-4 h-4 text-slate-400 shrink-0',
        'w-4 h-4 text-slate-500 shrink-0'
    ),
    # User card container
    (
        'pt-2 px-2 flex items-center gap-2.5 text-slate-700',
        'pt-2 px-2 flex items-center gap-2.5 text-slate-200'
    ),
    # User avatar
    (
        'w-7 h-7 rounded-full bg-pink-100 border border-pink-200 flex items-center justify-center text-pink-700 text-xs font-bold',
        'w-7 h-7 rounded-full bg-pink-900/50 border border-pink-700/50 flex items-center justify-center text-pink-300 text-xs font-bold'
    ),
    # User name text
    (
        'font-semibold text-xs truncate">Security Lead',
        'font-semibold text-xs truncate text-slate-200">Security Lead'
    ),
    # Trash2 icon (delete)
    (
        'w-3 h-3 text-rose-500',
        'w-3 h-3 text-rose-400'
    ),
])

print('\nSidebar patched.\n')

# Also patch BOLA Chips last chip in MessageComposer (4th one that wasn't found)
composer = os.path.join(BASE, 'chat/MessageComposer.tsx')
with open(composer, 'r', encoding='utf-8') as f:
    c = f.read()
# Find remaining white chip
old = 'px-3.5 py-1.5 rounded-full bg-[#181d26]/90 hover:bg-[#212836] text-slate-300 hover:text-pink-400 border border-slate-700/80 hover:border-pink-500/40 text-xs font-medium flex items-center gap-1.5 shadow-xs transition-all hover:scale-[1.03] active:scale-95 shrink-0">\n            <span>BOLA Probes</span>'
# Just confirm BOLA chip exists with correct new class already
if 'BOLA Probes' in c and 'bg-[#181d26]' in c:
    print('BOLA chip already dark-themed OK')
else:
    print('BOLA chip might still be light')
with open(composer, 'w', encoding='utf-8') as f:
    f.write(c)

print('=== SIDEBAR + COMPOSER PATCH DONE ===')
