#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"


def insert_after(text: str, anchor: str, addition: str, label: str) -> str:
    if addition.strip() in text:
        return text
    if anchor not in text:
        raise RuntimeError(f"{label}: anchor not found")
    return text.replace(anchor, anchor + addition, 1)


def ensure_import(text: str, import_line: str, anchor: str, label: str) -> str:
    line = import_line.rstrip("\n")
    if any(existing.strip() == line for existing in text.splitlines()):
        return text
    if anchor not in text:
        raise RuntimeError(f"{label}: import anchor not found")
    return text.replace(anchor, anchor + import_line, 1)


def main() -> None:
    text = UI.read_text(encoding="utf-8")
    original = text

    if "private fun DeobfuscationToolPanel" not in text:
        raise RuntimeError("deobfuscation UI must be applied before IO migration")

    text = ensure_import(
        text,
        "import androidx.compose.runtime.rememberCoroutineScope\n",
        "import androidx.compose.runtime.remember\n",
        "rememberCoroutineScope import",
    )
    # Add coroutine imports one-by-one. Older product screens already contain
    # Dispatchers/withContext, so inserting the whole block is not idempotent.
    for import_line in (
        "import kotlinx.coroutines.Dispatchers\n",
        "import kotlinx.coroutines.launch\n",
        "import kotlinx.coroutines.withContext\n",
    ):
        text = ensure_import(
            text,
            import_line,
            "import org.unirevlab.security.model.StaticAnalysisReport\n",
            f"{import_line.strip()} import",
        )

    text = insert_after(
        text,
        "private fun DeobfuscationToolPanel(report: StaticAnalysisReport) {\n    val context = LocalContext.current\n",
        "    val scope = rememberCoroutineScope()\n",
        "deobfuscation coroutine scope",
    )

    old = '''    val mappingPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                val text = readMappingTextBounded(context.contentResolver, uri)
                DeobfuscationEngine.parseMapping(text)
            }.onSuccess {
                mapping = it
                mappingError = null
            }.onFailure {
                mapping = null
                mappingError = it.message ?: it.javaClass.simpleName
            }
        }
    }
'''
    new = '''    val mappingPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        val text = readMappingTextBounded(context.contentResolver, uri)
                        DeobfuscationEngine.parseMapping(text)
                    }
                }
                result.onSuccess {
                    mapping = it
                    mappingError = null
                }.onFailure {
                    mapping = null
                    mappingError = it.message ?: it.javaClass.simpleName
                }
            }
        }
    }
'''
    if new not in text:
        if old not in text:
            raise RuntimeError("mapping picker block not found")
        text = text.replace(old, new, 1)

    if text != original:
        UI.write_text(text, encoding="utf-8")
        print("v0.26.5 mapping IO migration applied")
    else:
        print("v0.26.5 mapping IO migration already present")


if __name__ == "__main__":
    main()
