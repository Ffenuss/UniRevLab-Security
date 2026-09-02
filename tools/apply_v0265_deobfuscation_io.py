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


def main() -> None:
    text = UI.read_text(encoding="utf-8")
    original = text

    if "private fun DeobfuscationToolPanel" not in text:
        raise RuntimeError("deobfuscation UI must be applied before IO migration")

    text = insert_after(
        text,
        "import androidx.compose.runtime.remember\n",
        "import androidx.compose.runtime.rememberCoroutineScope\n",
        "rememberCoroutineScope import",
    )
    text = insert_after(
        text,
        "import org.unirevlab.security.model.StaticAnalysisReport\n",
        "import kotlinx.coroutines.Dispatchers\n"
        "import kotlinx.coroutines.launch\n"
        "import kotlinx.coroutines.withContext\n",
        "coroutine imports",
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
