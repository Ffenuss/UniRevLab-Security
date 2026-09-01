from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path, old, new, label):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'{label}: anchor not found in {path}')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')

# Patch Lab is intentionally converted from an always-expanded wall into collapsible tool sections.
# We keep state local to the screen so all existing engines/actions remain untouched.
path = 'app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt'
replace_once(path,
'''import androidx.compose.runtime.remember
''',
'''import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
''', 'mutable state import')

# Inject section state next to existing screen state. Anchor chosen from current v0.25.8 source.
replace_once(path,
'''    val scope = rememberCoroutineScope()
''',
'''    val scope = rememberCoroutineScope()
    var openToolSection by remember { mutableStateOf<String?>("assessment") }
''', 'section state')

# Add a tiny reusable section header inside the file before the main composable helpers.
marker = '\n@Composable\nprivate fun '
text = (ROOT / path).read_text(encoding='utf-8')
idx = text.find(marker)
if idx < 0:
    raise SystemExit('helper insertion point not found')
helper = '''\n@Composable\nprivate fun PatchLabSectionHeader(\n    title: String,\n    subtitle: String,\n    expanded: Boolean,\n    onClick: () -> Unit,\n) {\n    OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {\n        Column(modifier = Modifier.fillMaxWidth()) {\n            Text((if (expanded) "▼ " else "▶ ") + title, style = MaterialTheme.typography.titleMedium)\n            if (subtitle.isNotBlank()) Text(subtitle, style = MaterialTheme.typography.bodySmall)\n        }\n    }\n}\n'''
text = text[:idx] + helper + text[idx:]
(ROOT / path).write_text(text, encoding='utf-8')

# The large panels are wrapped by headers. These exact calls exist in v0.25.8.
wraps = [
    ('TamperAssessmentPanel(', 'assessment', 'Tamper Assessment', 'Риски, поверхности, секреты и ручной поиск'),
    ('AutoModPanel(', 'automod', 'AutoMod Demo', 'Автоматические демонстрационные изменения'),
    ('RuntimeStateLabPanel(', 'runtime', 'Runtime State Lab', 'Локальные сохранения и state-файлы'),
]
for call, key, title, subtitle in wraps:
    p = ROOT / path
    src = p.read_text(encoding='utf-8')
    pos = src.find(call)
    if pos < 0:
        raise SystemExit(f'{call} not found')
    line_start = src.rfind('\n', 0, pos) + 1
    indent = src[line_start:pos]
    # Find the full balanced call expression.
    depth = 0
    i = pos
    seen = False
    while i < len(src):
        ch = src[i]
        if ch == '(':
            depth += 1; seen = True
        elif ch == ')':
            depth -= 1
            if seen and depth == 0:
                i += 1
                break
        i += 1
    original = src[pos:i]
    replacement = f'''PatchLabSectionHeader(\n{indent}    title = "{title}",\n{indent}    subtitle = "{subtitle}",\n{indent}    expanded = openToolSection == "{key}",\n{indent}    onClick = {{ openToolSection = if (openToolSection == "{key}") null else "{key}" }},\n{indent})\n{indent}if (openToolSection == "{key}") {{\n{indent}    {original}\n{indent}}}'''
    src = src[:pos] + replacement + src[i:]
    p.write_text(src, encoding='utf-8')

print('v0.25.9 compact Patch Lab sections applied')
