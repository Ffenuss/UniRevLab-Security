from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path, old, new, label):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'{label}: anchor not found in {path}')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')

path = 'app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt'
p = ROOT / path
text = p.read_text(encoding='utf-8')

if 'var openToolSection by remember' not in text:
    old = '''    val context = LocalContext.current
    val scope = rememberCoroutineScope()
'''
    new = '''    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var openToolSection by remember { mutableStateOf<String?>("assessment") }
'''
    if old not in text:
        raise SystemExit('section state: anchor not found in PatchLabScreen.kt')
    text = text.replace(old, new, 1)

if 'private fun PatchLabSectionHeader(' not in text:
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

def wrap_first(calls, key, title, subtitle):
    p = ROOT / path
    src = p.read_text(encoding='utf-8')
    # Treat already-migrated sections as complete even if an earlier patch changed
    # whitespace or the exact panel call name. This keeps CI migrations idempotent.
    if f'title = "{title}"' in src and f'openToolSection == "{key}"' in src:
        return
    call = next((candidate for candidate in calls if candidate in src), None)
    if call is None:
        raise SystemExit(f'none of panel calls found: {calls}')
    pos = src.find(call)
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
    p.write_text(src[:pos] + replacement + src[i:], encoding='utf-8')

wrap_first(['TamperAssessmentPanelV2(', 'TamperAssessmentPanel('], 'assessment', 'Tamper Assessment', 'Риски, поверхности, секреты и ручной поиск')
wrap_first(['AutoModPanel('], 'automod', 'AutoMod Demo', 'Автоматические демонстрационные изменения')
wrap_first(['RuntimeStateLabPanel('], 'runtime', 'Runtime State Lab', 'Локальные сохранения и state-файлы')

print('v0.25.9 compact Patch Lab sections applied/already present')
