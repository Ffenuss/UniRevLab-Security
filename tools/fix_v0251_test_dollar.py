from pathlib import Path

path = Path("app/src/test/java/org/unirevlab/security/analysis/TamperAssessmentEngineTest.kt")
text = path.read_text(encoding="utf-8")
old = "ICustomTabsService$Default;"
new = "ICustomTabsService\\$Default;"
if old in text:
    text = text.replace(old, new)
elif new not in text:
    raise SystemExit("v0.25.1 test escape anchor not found")
path.write_text(text, encoding="utf-8")
print("v0.25.1 Kotlin dollar escaping fixed")
