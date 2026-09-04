package org.unirevlab.security.analysis

import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSymbolReference
import org.unirevlab.security.model.StaticAnalysisReport

/** Human-readable, searchable companion to offset-evidence.json. */
object OffsetReadableExporter {
    fun write(report: StaticAnalysisReport, out: Appendable) {
        val libraries = report.native?.libraries.orEmpty()
        val libraryByEntry = libraries.associateBy(NativeLibrarySummary::entryName)
        val il2cppMappings = report.correlations?.il2cppMethods.orEmpty()
            .sortedWith(compareBy({ it.libraryEntry }, { it.declaringType }, { it.methodName }, { it.functionRva }))
            .take(MAX_IL2CPP_MAPPING_ROWS)
        val jniMappings = report.correlations?.jniNative.orEmpty()
            .sortedWith(compareBy({ it.libraryEntry }, { it.declaringClass }, { it.methodName }, { it.functionRva }))
            .take(MAX_JNI_MAPPING_ROWS)
        val registrationCandidates = report.il2cpp?.registrationCandidates.orEmpty()
            .sortedWith(compareBy({ it.libraryEntry }, { it.virtualAddress }, { it.kind }))
            .take(MAX_REGISTRATION_ROWS)
        val rawSymbols = fairNativeSymbols(libraries)

        val allIl2cppMappings = report.correlations?.il2cppMethods.orEmpty().size
        val allJniMappings = report.correlations?.jniNative.orEmpty().size
        val allRegistrations = report.il2cpp?.registrationCandidates.orEmpty().size
        val allRawSymbols = libraries.sumOf { library ->
            (library.exportedSymbols + library.importedSymbols)
                .asSequence()
                .filter { it.defined && it.virtualAddress != null }
                .distinctBy { it.name to it.virtualAddress }
                .count()
        }

        out.line("<!doctype html>")
        out.line("<html lang=\"ru\"><head><meta charset=\"utf-8\">")
        out.line("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
        out.line("<title>Понятный экспорт офсетов — ${html(report.artifact.displayName)}</title>")
        out.line(STYLE)
        out.line("</head><body><main>")
        out.line("<header><div class=\"eyebrow\">UNIREVLAB · ПОНЯТНЫЕ ОФСЕТЫ</div>")
        out.line("<h1>${html(report.artifact.displayName)}</h1>")
        out.line("<p class=\"muted\">SHA-256: <code>${html(report.artifact.sha256)}</code><br>Движок: <code>${html(report.engineVersion)}</code></p></header>")

        out.line("<section class=\"cards\">")
        metric(out, "Подтверждённые IL2CPP", allIl2cppMappings, "method → native RVA")
        metric(out, "Связанные JNI", allJniMappings, "DEX → native RVA")
        metric(out, "Кандидаты registration", allRegistrations, "требуют проверки")
        metric(out, "Native-символы", allRawSymbols, "сырой ELF inventory")
        out.line("</section>")

        if (allIl2cppMappings == 0) {
            out.line("<section class=\"notice warn\"><strong>Подтверждённых IL2CPP method → RVA связок нет.</strong> " +
                "Имена из раздела Native ниже нельзя автоматически считать игровыми методами. " +
                "Полный каталог managed-методов без доказанного адреса находится в <code>il2cpp-dump.cs</code>.</section>")
        } else {
            out.line("<section class=\"notice ok\"><strong>Есть подтверждённые IL2CPP-связки.</strong> " +
                "Начинайте с зелёных строк: metadata-метод связан с конкретной native-функцией и RVA.</section>")
        }

        out.line("<section><h2>Как читать таблицу</h2><ul>")
        out.line("<li><strong>RVA</strong> — адрес относительно базы загрузки указанной библиотеки, не абсолютный адрес памяти.</li>")
        out.line("<li>Всегда учитывайте одновременно <strong>библиотеку, ABI, Build ID и RVA</strong>.</li>")
        out.line("<li><strong>FUNC</strong> — native-функция, <strong>OBJECT</strong> — данные, <strong>NOTYPE</strong> — обычно служебная метка.</li>")
        out.line("<li>Расшифрованное имя — удобное представление; оригинальное техническое имя сохранено рядом.</li>")
        out.line("</ul></section>")

        out.line("<section class=\"explorer\"><div class=\"toolbar\"><div><h2>Единая таблица evidence</h2>" +
            "<p id=\"visibleCount\" class=\"muted\"></p></div>")
        out.line("<label>Поиск<input id=\"search\" type=\"search\" placeholder=\"Класс, метод, библиотека, RVA…\" oninput=\"applyFilters()\"></label>")
        out.line("<label>Тип<select id=\"kind\" onchange=\"applyFilters()\"><option value=\"\">Все</option>" +
            "<option value=\"il2cpp\">IL2CPP method</option><option value=\"jni\">JNI bridge</option>" +
            "<option value=\"registration\">Registration</option><option value=\"native\">Native FUNC</option>" +
            "<option value=\"data\">OBJECT</option><option value=\"service\">NOTYPE</option></select></label></div>")
        out.line("<div class=\"table-wrap\"><table><thead><tr><th>Статус</th><th>Тип</th><th>Библиотека / ABI</th>" +
            "<th>Понятное имя</th><th>RVA</th><th>Token / размер</th><th>Что означает</th></tr></thead><tbody id=\"rows\">")

        il2cppMappings.forEach { method ->
            val library = libraryByEntry[method.libraryEntry]
            row(out, "il2cpp", "Подтверждено", "confirmed", "IL2CPP method", method.libraryEntry,
                library?.abi, library?.buildId, "${method.declaringType}.${method.methodName}(…)", method.functionName,
                method.functionRva, hex(method.token), null,
                "Metadata-метод связан с native-функцией. Confidence: ${method.confidence}. ${method.evidence}")
        }
        jniMappings.forEach { method ->
            val library = libraryByEntry[method.libraryEntry]
            row(out, "jni", "Связано", "confirmed", "JNI bridge", method.libraryEntry,
                library?.abi, library?.buildId, "${method.declaringClass}.${method.methodName}${method.prototype}",
                method.functionName ?: "—", method.functionRva, null, null,
                "DEX native-метод связан с ELF-функцией. Confidence: ${method.confidence}. ${method.evidence}")
        }
        registrationCandidates.forEach { candidate ->
            val library = libraryByEntry[candidate.libraryEntry]
            row(out, "registration", if (candidate.validatedDefinedSymbol) "Проверен" else "Кандидат",
                if (candidate.validatedDefinedSymbol) "confirmed" else "candidate", "IL2CPP registration",
                candidate.libraryEntry, library?.abi, library?.buildId, candidate.kind, candidate.symbolName,
                candidate.virtualAddress, null, candidate.sizeBytes,
                "Служебная структура регистрации IL2CPP, а не игровой метод.")
        }
        rawSymbols.forEach { (library, symbol) ->
            val kind = when (symbol.symbolType.uppercase()) {
                "FUNC" -> "native"
                "OBJECT" -> "data"
                else -> "service"
            }
            row(out, kind, "Справочно", "reference", symbol.symbolType, library.entryName, library.abi,
                library.buildId, readableSymbolName(symbol), symbol.name, symbol.virtualAddress, null,
                symbol.sizeBytes, describeSymbol(symbol))
        }

        out.line("</tbody></table></div>")
        val truncated = allIl2cppMappings > il2cppMappings.size || allJniMappings > jniMappings.size ||
            allRegistrations > registrationCandidates.size || allRawSymbols > rawSymbols.size
        if (truncated) {
            out.line("<p class=\"notice warn\">Таблица ограничена для нормальной работы телефона. " +
                "Полный набор без сокращений сохранён в <code>offset-evidence.json</code>.</p>")
        }
        out.line("</section>")
        out.line(SCRIPT)
        out.line("</main></body></html>")
    }

    private fun metric(out: Appendable, title: String, value: Int, subtitle: String) {
        out.line("<article class=\"metric\"><span>${html(title)}</span><strong>$value</strong><small>${html(subtitle)}</small></article>")
    }

    private fun row(
        out: Appendable, kind: String, status: String, statusClass: String, type: String,
        library: String, abi: String?, buildId: String?, readableName: String, technicalName: String,
        rva: Long?, token: String?, sizeBytes: Long?, meaning: String,
    ) {
        val technical = technicalName.takeIf { it != readableName }
            ?.let { "<small><code>${html(it)}</code></small>" }.orEmpty()
        val identity = buildString {
            append("<code>").append(html(library)).append("</code>")
            abi?.let { append("<small>ABI: ").append(html(it)).append("</small>") }
            buildId?.let { append("<small>Build ID: ").append(html(it.take(24))).append("</small>") }
        }
        val tokenAndSize = buildList {
            token?.let { add("token $it") }
            sizeBytes?.let { add("$it байт") }
        }.joinToString("<br>").ifBlank { "—" }
        out.line("<tr data-kind=\"${html(kind)}\"><td><span class=\"status ${html(statusClass)}\">${html(status)}</span></td>" +
            "<td>${html(type)}</td><td>$identity</td><td><strong>${html(readableName)}</strong>$technical</td>" +
            "<td><code>${rva?.let(::hex) ?: "—"}</code></td><td>$tokenAndSize</td><td>${html(compact(meaning))}</td></tr>")
    }

    private fun readableSymbolName(symbol: NativeSymbolReference): String {
        val name = symbol.name
        if (name.startsWith("Java_")) return "JNI · " + name.removePrefix("Java_")
            .substringBefore("__").replace("_1", "_").replace('_', '.')
        if (!name.startsWith("_ZN")) return name
        val parts = mutableListOf<String>()
        var cursor = 3
        while (cursor < name.length && name[cursor] != 'E') {
            when {
                name[cursor].isDigit() -> {
                    val lengthStart = cursor
                    while (cursor < name.length && name[cursor].isDigit()) cursor++
                    val length = name.substring(lengthStart, cursor).toIntOrNull() ?: return name
                    if (length <= 0 || cursor + length > name.length) return name
                    parts += name.substring(cursor, cursor + length)
                    cursor += length
                }
                name.startsWith("D0", cursor) || name.startsWith("D1", cursor) || name.startsWith("D2", cursor) -> {
                    val owner = parts.lastOrNull() ?: return name
                    parts += "~$owner"
                    cursor += 2
                }
                name.startsWith("C1", cursor) || name.startsWith("C2", cursor) || name.startsWith("C3", cursor) -> {
                    parts += parts.lastOrNull() ?: return name
                    cursor += 2
                }
                else -> return name
            }
        }
        if (cursor >= name.length || name[cursor] != 'E' || parts.isEmpty()) return name
        val readable = parts.joinToString("::")
        return if (symbol.symbolType.equals("FUNC", ignoreCase = true)) "$readable(…)" else readable
    }

    private fun fairNativeSymbols(
        libraries: List<NativeLibrarySummary>,
    ): List<Pair<NativeLibrarySummary, NativeSymbolReference>> {
        if (libraries.isEmpty()) return emptyList()
        val catalogs = libraries.map { library ->
            (library.exportedSymbols + library.importedSymbols)
                .asSequence()
                .filter { it.defined && it.virtualAddress != null }
                .distinctBy { it.name to it.virtualAddress }
                .sortedWith(compareBy({ it.virtualAddress }, { it.name }))
                .toList()
        }
        val guaranteed = minOf(MIN_NATIVE_SYMBOL_ROWS_PER_LIBRARY, MAX_NATIVE_SYMBOL_ROWS / libraries.size)
        val selected = catalogs.map { it.take(guaranteed).toMutableList() }
        var remaining = (MAX_NATIVE_SYMBOL_ROWS - selected.sumOf { it.size }).coerceAtLeast(0)
        while (remaining > 0) {
            var added = false
            for (index in libraries.indices) {
                val next = selected[index].size
                if (next >= catalogs[index].size) continue
                selected[index] += catalogs[index][next]
                remaining--
                added = true
                if (remaining == 0) break
            }
            if (!added) break
        }
        return libraries.indices.flatMap { index ->
            selected[index].map { symbol -> libraries[index] to symbol }
        }
    }

    private fun describeSymbol(symbol: NativeSymbolReference): String {
        val name = symbol.name.lowercase()
        return when {
            symbol.symbolType.equals("NOTYPE", true) ->
                "Служебная метка ELF/линкера; обычно не является вызываемой функцией."
            symbol.symbolType.equals("OBJECT", true) ->
                "Глобальный объект или переменная данных; это не адрес функции."
            name.startsWith("il2cpp_") || name.contains("il2cpp") ->
                "Функция runtime IL2CPP; сама по себе не является подтверждённым managed-методом приложения."
            listOf("crash", "logger", "writelog", "reportexception", "analytics", "bugly").any { marker -> name.contains(marker) } ->
                "Похоже на функцию журналирования, аналитики или crash-reporting SDK; не подтверждённый игровой метод."
            else -> "Экспортированная native-функция. Назначение требует проверки по контексту и evidence."
        }
    }

    private fun compact(value: String): String = value.replace(Regex("\\s+"), " ").trim().take(MAX_MEANING_CHARS)
    private fun hex(value: Long): String = "0x" + value.toString(16)
    private fun html(value: String): String = buildString(value.length) {
        value.forEach { char ->
            append(when (char) {
                '&' -> "&amp;"
                '<' -> "&lt;"
                '>' -> "&gt;"
                '"' -> "&quot;"
                '\'' -> "&#39;"
                else -> char
            })
        }
    }
    private fun Appendable.line(value: String) { append(value).append('\n') }

    private const val MAX_IL2CPP_MAPPING_ROWS = 5_000
    private const val MAX_JNI_MAPPING_ROWS = 2_000
    private const val MAX_REGISTRATION_ROWS = 1_000
    private const val MAX_NATIVE_SYMBOL_ROWS = 5_000
    private const val MIN_NATIVE_SYMBOL_ROWS_PER_LIBRARY = 32
    private const val MAX_MEANING_CHARS = 320

    private val STYLE = """
        <style>
        :root{color-scheme:dark;--bg:#0b101b;--card:#111a2b;--line:#27334a;--text:#edf2ff;--muted:#aeb8ce;--accent:#9d6cff}
        *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,sans-serif}
        main{max-width:1500px;margin:auto;padding:24px}header{padding:12px 0 8px}.eyebrow{color:#70d7ef;font-size:12px;font-weight:800;letter-spacing:.14em}
        h1{font-size:clamp(26px,5vw,44px);margin:.2em 0}h2{margin:.2em 0 12px}.muted,small{color:var(--muted)}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
        section{margin:18px 0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.metric,.notice,.explorer{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px}
        .metric{display:flex;flex-direction:column}.metric strong{font-size:30px;color:var(--accent)}.notice.ok{border-color:#267b60}.notice.warn{border-color:#9b6a2c}
        .toolbar{display:flex;gap:12px;align-items:end;flex-wrap:wrap}.toolbar>div{flex:1 1 320px}.toolbar label{display:flex;flex-direction:column;color:var(--muted);font-size:12px;gap:5px}
        input,select{min-height:44px;background:#0b1322;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:9px 11px;font:inherit}
        .table-wrap{overflow:auto;margin-top:14px;max-height:72vh;border:1px solid var(--line);border-radius:12px}table{border-collapse:collapse;width:100%;min-width:1080px}
        th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line)}th{position:sticky;top:0;background:#182238;z-index:1}td small{display:block;margin-top:4px}
        .status{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:750}.confirmed{background:#173f34;color:#6ff2ba}.candidate{background:#4a3517;color:#ffd18b}.reference{background:#283247;color:#c7d1e6}
        tr[hidden]{display:none}@media(max-width:700px){main{padding:14px}.explorer{padding:10px}.table-wrap{max-height:68vh}}
        </style>
    """.trimIndent()

    private val SCRIPT = """
        <script>
        function applyFilters(){
          const q=document.getElementById('search').value.toLowerCase().trim();
          const kind=document.getElementById('kind').value;
          let visible=0;
          document.querySelectorAll('#rows tr').forEach(row=>{
            const show=(!kind||row.dataset.kind===kind)&&(!q||row.textContent.toLowerCase().includes(q));
            row.hidden=!show;if(show)visible++;
          });
          document.getElementById('visibleCount').textContent='Показано строк: '+visible;
        }
        applyFilters();
        </script>
    """.trimIndent()
}
