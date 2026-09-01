from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path, old, new, label):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'{label}: anchor not found in {path}')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')

path = 'app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt'

# mutableStateOf is already part of PatchLabScreen state; add only the section state.
replace_once(path,
'''    val context = LocalContext.current
    val scope = rememberCoroutineScope()
''',
'''    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var openToolSection by remember { mutableStateOf<String?>("assessment") }
''', 'section state')

# Insert reusable compact header directly before PatchLabScreen.
p = ROOT / path
text = p.read_text(encoding='utf-8')
marker = '@Composable\nfun PatchLabScreen('
idx = text.find(marker)
if idx < 0:
    raise SystemExit('PatchLabScreen insertion point not found')
helper = '''@Composable
private fun PatchLabSectionHeader(
    title: String,
    subtitle: String,
    expanded: Boolean,
    onClick: () -> Unit,
) {
    OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Text((if (expanded) "▼ " else "▶ ") + title, style = MaterialTheme.typography.titleMedium)
            if (subtitle.isNotBlank()) Text(subtitle, style = MaterialTheme.typography.bodySmall)
        }
    }
}

'''
text = text[:idx] + helper + text[idx:]
p.write_text(text, encoding='utf-8')

# Wrap the three largest always-expanded tools. Balanced-call parsing avoids depending on argument layout.
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
    depth = 0
    i = pos
    seen = False
    in_string = False
    escaped = False
    while i < len(src):
        ch = src[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == '(':
                depth += 1
                seen = True
            elif ch == ')':
                depth -= 1
                if seen and depth == 0:
                    i += 1
                    break
        i += 1
    if depth != 0:
        raise SystemExit(f'unbalanced call: {call}')
    original = src[pos:i]
    replacement = f'''PatchLabSectionHeader(
{indent}    title = "{title}",
{indent}    subtitle = "{subtitle}",
{indent}    expanded = openToolSection == "{key}",
{indent}    onClick = {{ openToolSection = if (openToolSection == "{key}") null else "{key}" }},
{indent})
{indent}if (openToolSection == "{key}") {{
{indent}    {original}
{indent}}}'''
    src = src[:pos] + replacement + src[i:]
    p.write_text(src, encoding='utf-8')

print('v0.25.9 compact Patch Lab sections applied')
