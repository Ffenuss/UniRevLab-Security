#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIR = ROOT / "app/src/main/java/org/unirevlab/security/ui/Il2CppPairWorkspaceScreen.kt"
PRODUCT = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"

pair = PAIR.read_text(encoding="utf-8")
pair = pair.replace("InfoCard(", "PairInfoCard(")
if "private fun PairInfoCard(" not in pair:
    anchor = '''private fun queryDisplayName(context: Context, uri: Uri): String? = runCatching {\n'''
    helper = '''@Composable\nprivate fun PairInfoCard(text: String) {\n    Card(shape = RoundedCornerShape(16.dp)) {\n        Text(text, modifier = Modifier.padding(13.dp), style = MaterialTheme.typography.bodySmall)\n    }\n}\n\n'''
    if anchor not in pair:
        raise SystemExit("Il2CppPairWorkspaceScreen: helper anchor missing")
    pair = pair.replace(anchor, helper + anchor, 1)
PAIR.write_text(pair, encoding="utf-8")

product = PRODUCT.read_text(encoding="utf-8")
product = product.replace(
    "import androidx.compose.runtime.getValue\nimport androidx.compose.runtime.getValue\n",
    "import androidx.compose.runtime.getValue\n",
)
PRODUCT.write_text(product, encoding="utf-8")
print("v0.33 IL2CPP compile guard applied")
