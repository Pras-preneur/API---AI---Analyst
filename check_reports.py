"""
Fix the reports section header border in App.tsx 
(second occurrence that wasn't found by the first replace)
"""
path = r'd:\Team - Zynora - Hackathon\API - Ai -  Analyst\frontend\src\App.tsx'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# The reports heading now has border-slate-700/60 still needed for its header
# Find current state
import re

# Find reports section: look for "Security Assessment Reports"
idx = content.find('Security Assessment Reports')
if idx == -1:
    print('Security Assessment Reports not found!')
else:
    # Get context around it
    chunk = content[max(0,idx-300):idx+100]
    print('CONTEXT:')
    print(repr(chunk))
