from pathlib import Path

path = Path('app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt')
text = path.read_text()

old = '''                TamperAssessmentPanel(
                    report = report,
                    workspace = ws,
                    busy = busy,
                    onOpenTarget = ::openTamperTarget,
                    onApplyHook = ::applyGeneratedTraceHook,
                    onStatus = { status = it },
                    onError = { error = it },
                )'''
new = old.replace('TamperAssessmentPanel(', 'TamperAssessmentPanelV2(')
if old in text:
    text = text.replace(old, new, 1)
elif 'TamperAssessmentPanelV2(' not in text:
    raise SystemExit('TamperAssessmentPanel call not found')

auto = '''                AutoModPanel(
                    report = report,
                    workspace = ws,
                    busy = busy,
                    onAnalyzeBuilt = onAnalyzeBuilt,
                    onStatus = { status = it },
                    onError = { error = it },
                )'''
runtime = auto + '''
                RuntimeStateLabPanel(
                    busy = busy,
                    onStatus = { status = it },
                    onError = { error = it },
                )'''
if 'RuntimeStateLabPanel(' not in text:
    if auto not in text:
        raise SystemExit('AutoModPanel block not found')
    text = text.replace(auto, runtime, 1)

path.write_text(text)
