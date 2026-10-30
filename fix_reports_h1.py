path = r'd:\Team - Zynora - Hackathon\API - Ai -  Analyst\frontend\src\App.tsx'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Find and fix the reports h1 that still has text-slate-800
old = 'text-2xl font-bold text-slate-800 font-heading">\n                    Security Assessment Reports'
new = 'text-2xl font-bold text-slate-100 font-heading">\n                    Security Assessment Reports'
if old in content:
    content = content.replace(old, new)
    print('[OK] Fixed reports h1')
else:
    print('[!!] NOT FOUND - reports h1')
    # Try to show what's there
    idx = content.find('Security Assessment Reports')
    print('CONTEXT:', repr(content[max(0,idx-200):idx+50]))

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print('Done')
