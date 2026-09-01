from pathlib import Path
p = Path(__file__).with_name("apply_v0258_apkset_sources.py")
s = p.read_text(encoding="utf-8")
old = 'def replace_once(text, old, new, label):\n'
new = 'def replace_once(text, old, new, label="patch"):\n'
if old not in s and new not in s:
    raise SystemExit("replace_once signature not found")
if old in s:
    s = s.replace(old, new, 1)
p.write_text(s, encoding="utf-8")
print("v0.25.8 patch driver fixed")
