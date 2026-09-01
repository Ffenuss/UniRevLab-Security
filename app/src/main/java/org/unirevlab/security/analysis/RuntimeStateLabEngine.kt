package org.unirevlab.security.analysis

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import java.io.File
import java.security.MessageDigest
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

/**
 * Runtime State Lab works only with a user-selected/exported data tree that Android grants us.
 * It does not bypass another application's sandbox. For customer/debug builds the selected tree can
 * be an exported snapshot or an app-controlled external/debug data directory.
 */
object RuntimeStateLabEngine {
    enum class Format { SHARED_PREFS_XML, JSON, PROPERTIES, TEXT, SQLITE }
    enum class ValueType { BOOLEAN, INTEGER, LONG, FLOAT, STRING, NULL, OTHER }

    data class StateHit(
        val id: String,
        val documentUri: String,
        val path: String,
        val format: Format,
        val key: String,
        val value: String,
        val valueType: ValueType,
        val writable: Boolean,
        val locator: Locator,
    )

    sealed interface Locator {
        data class TextLine(val lineNumber: Int, val separator: String?) : Locator
        data class XmlKey(val name: String) : Locator
        data class JsonPath(val segments: List<String>) : Locator
        data class SqlCell(val table: String, val rowId: Long?, val column: String) : Locator
    }

    data class SearchReport(
        val hits: List<StateHit>,
        val filesScanned: Int,
        val sqliteTablesScanned: Int,
        val warnings: List<String>,
    )

    fun search(context: Context, treeUri: Uri, rawQuery: String): SearchReport {
        val query = rawQuery.trim()
        require(query == "*" || query.length >= 2) { "Введите минимум 2 символа или * для показа всех распознанных значений" }
        val root = requireNotNull(DocumentFile.fromTreeUri(context, treeUri)) { "Не удалось открыть выбранное дерево данных" }
        require(root.exists() && root.isDirectory) { "Выбранный URI не является доступной папкой" }

        val hits = mutableListOf<StateHit>()
        val warnings = mutableListOf<String>()
        var filesScanned = 0
        var sqliteTables = 0
        val visited = hashSetOf<String>()

        fun walk(node: DocumentFile, path: String) {
            val uriKey = node.uri.toString()
            if (!visited.add(uriKey)) return
            if (node.isDirectory) {
                val children = runCatching { node.listFiles() }.getOrElse {
                    warnings += "$path: не удалось перечислить файлы (${it.message})"
                    emptyArray()
                }
                children.forEach { child ->
                    val name = child.name ?: "(без имени)"
                    walk(child, if (path.isBlank()) name else "$path/$name")
                }
                return
            }
            if (!node.isFile) return
            val name = node.name.orEmpty()
            val format = detectFormat(name) ?: return
            filesScanned++
            when (format) {
                Format.SQLITE -> {
                    val result = runCatching { searchSqlite(context, node, path, query) }
                    result.onSuccess {
                        hits += it.first
                        sqliteTables += it.second
                    }.onFailure { warnings += "$path: SQLite не прочитан (${it.message})" }
                }
                else -> {
                    val result = runCatching { searchTextDocument(context, node, path, format, query) }
                    result.onSuccess { hits += it }
                        .onFailure { warnings += "$path: файл не прочитан (${it.message})" }
                }
            }
        }

        walk(root, root.name.orEmpty())
        return SearchReport(
            hits = hits.distinctBy { it.id },
            filesScanned = filesScanned,
            sqliteTablesScanned = sqliteTables,
            warnings = warnings.distinct(),
        )
    }

    fun edit(context: Context, hit: StateHit, newValueRaw: String): StateHit {
        require(hit.writable) { "Выбранный документ доступен только для чтения" }
        val uri = Uri.parse(hit.documentUri)
        ensureBackup(context, uri)
        return when (hit.format) {
            Format.SQLITE -> editSqlite(context, uri, hit, newValueRaw)
            Format.JSON -> editJson(context, uri, hit, newValueRaw)
            Format.SHARED_PREFS_XML -> editXml(context, uri, hit, newValueRaw)
            Format.PROPERTIES, Format.TEXT -> editTextLine(context, uri, hit, newValueRaw)
        }
    }

    fun hasBackup(context: Context, documentUri: String): Boolean = backupFile(context, Uri.parse(documentUri)).isFile

    fun restore(context: Context, documentUri: String) {
        val uri = Uri.parse(documentUri)
        val backup = backupFile(context, uri)
        require(backup.isFile) { "Backup для этого файла не найден" }
        context.contentResolver.openOutputStream(uri, "wt").use { output ->
            requireNotNull(output) { "Не удалось открыть исходный файл для восстановления" }
            backup.inputStream().buffered(COPY_BUFFER).use { input -> input.copyTo(output, COPY_BUFFER) }
            output.flush()
        }
    }

    private fun searchTextDocument(
        context: Context,
        document: DocumentFile,
        path: String,
        format: Format,
        query: String,
    ): List<StateHit> {
        val text = readText(context, document.uri)
        val writable = document.canWrite()
        return when (format) {
            Format.SHARED_PREFS_XML -> parseSharedPrefs(document.uri, path, text, query, writable)
            Format.JSON -> parseJson(document.uri, path, text, query, writable)
            Format.PROPERTIES -> parseProperties(document.uri, path, text, query, writable)
            Format.TEXT -> parseGenericText(document.uri, path, text, query, writable)
            Format.SQLITE -> emptyList()
        }
    }

    private fun parseSharedPrefs(uri: Uri, path: String, text: String, query: String, writable: Boolean): List<StateHit> {
        val out = mutableListOf<StateHit>()
        val selfClosing = Regex("""<\s*(boolean|int|long|float)\b([^>]*?\bname\s*=\s*\"([^\"]+)\"[^>]*?\bvalue\s*=\s*\"([^\"]*)\"[^>]*)/\s*>""", RegexOption.IGNORE_CASE)
        selfClosing.findAll(text).forEach { match ->
            val key = unescapeXml(match.groupValues[3])
            val value = unescapeXml(match.groupValues[4])
            if (!matches(query, key, value)) return@forEach
            val type = when (match.groupValues[1].lowercase(Locale.ROOT)) {
                "boolean" -> ValueType.BOOLEAN
                "int" -> ValueType.INTEGER
                "long" -> ValueType.LONG
                "float" -> ValueType.FLOAT
                else -> ValueType.OTHER
            }
            out += hit(uri, path, Format.SHARED_PREFS_XML, key, value, type, writable, Locator.XmlKey(key))
        }
        val stringRegex = Regex("""<\s*string\b[^>]*?\bname\s*=\s*\"([^\"]+)\"[^>]*>(.*?)<\s*/\s*string\s*>""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
        stringRegex.findAll(text).forEach { match ->
            val key = unescapeXml(match.groupValues[1])
            val value = unescapeXml(match.groupValues[2].trim())
            if (matches(query, key, value)) out += hit(uri, path, Format.SHARED_PREFS_XML, key, value, ValueType.STRING, writable, Locator.XmlKey(key))
        }
        return out
    }

    private fun parseJson(uri: Uri, path: String, text: String, query: String, writable: Boolean): List<StateHit> {
        val trimmed = text.trim()
        val root: Any = when {
            trimmed.startsWith("{") -> JSONObject(trimmed)
            trimmed.startsWith("[") -> JSONArray(trimmed)
            else -> return parseGenericText(uri, path, text, query, writable)
        }
        val out = mutableListOf<StateHit>()
        fun visit(value: Any?, segments: List<String>, keyLabel: String) {
            when (value) {
                is JSONObject -> value.keys().forEach { key -> visit(value.opt(key), segments + "o:$key", key) }
                is JSONArray -> for (i in 0 until value.length()) visit(value.opt(i), segments + "a:$i", "[$i]")
                JSONObject.NULL, null -> {
                    if (matches(query, keyLabel, "null")) out += hit(uri, path, Format.JSON, keyLabel, "null", ValueType.NULL, writable, Locator.JsonPath(segments))
                }
                else -> {
                    val rendered = value.toString()
                    if (matches(query, keyLabel, rendered)) {
                        out += hit(uri, path, Format.JSON, keyLabel, rendered, valueType(value), writable, Locator.JsonPath(segments))
                    }
                }
            }
        }
        visit(root, emptyList(), "$")
        return out
    }

    private fun parseProperties(uri: Uri, path: String, text: String, query: String, writable: Boolean): List<StateHit> {
        val out = mutableListOf<StateHit>()
        text.lineSequence().forEachIndexed { index, line ->
            val trimmed = line.trim()
            if (trimmed.isBlank() || trimmed.startsWith("#") || trimmed.startsWith(";")) return@forEachIndexed
            val match = Regex("""^\s*([^:=\s][^:=]*?)\s*([:=])\s*(.*?)\s*$""").matchEntire(line) ?: return@forEachIndexed
            val key = match.groupValues[1].trim()
            val separator = match.groupValues[2]
            val value = match.groupValues[3]
            if (matches(query, key, value)) out += hit(uri, path, Format.PROPERTIES, key, value, inferStringType(value), writable, Locator.TextLine(index + 1, separator))
        }
        return out
    }

    private fun parseGenericText(uri: Uri, path: String, text: String, query: String, writable: Boolean): List<StateHit> {
        val out = mutableListOf<StateHit>()
        text.lineSequence().forEachIndexed { index, line ->
            val match = Regex("""^\s*([A-Za-z0-9_.\-\[\]/]{1,180})\s*([:=])\s*(.*?)\s*$""").matchEntire(line)
            if (match != null) {
                val key = match.groupValues[1]
                val value = match.groupValues[3]
                if (matches(query, key, value)) out += hit(uri, path, Format.TEXT, key, value, inferStringType(value), writable, Locator.TextLine(index + 1, match.groupValues[2]))
            } else if (query != "*" && line.contains(query, ignoreCase = true)) {
                out += hit(uri, path, Format.TEXT, "line ${index + 1}", line, ValueType.STRING, writable, Locator.TextLine(index + 1, null))
            }
        }
        return out
    }

    private fun searchSqlite(context: Context, document: DocumentFile, path: String, query: String): Pair<List<StateHit>, Int> {
        val temp = copyToTemp(context, document.uri, "scan-${sha256(document.uri.toString()).take(16)}.db")
        val out = mutableListOf<StateHit>()
        var tableCount = 0
        SQLiteDatabase.openDatabase(temp.absolutePath, null, SQLiteDatabase.OPEN_READONLY).use { db ->
            val tables = mutableListOf<String>()
            db.rawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", null).use { cursor ->
                while (cursor.moveToNext()) tables += cursor.getString(0)
            }
            for (table in tables) {
                tableCount++
                val sql = "SELECT rowid,* FROM ${quoteIdent(table)}"
                val cursor = runCatching { db.rawQuery(sql, null) }.getOrNull() ?: continue
                cursor.use {
                    while (it.moveToNext()) {
                        val rowId = runCatching { it.getLong(0) }.getOrNull()
                        for (columnIndex in 1 until it.columnCount) {
                            if (it.isNull(columnIndex)) continue
                            val column = it.getColumnName(columnIndex)
                            val value = cursorValue(it, columnIndex) ?: continue
                            if (!matches(query, column, value)) continue
                            out += hit(
                                document.uri,
                                path,
                                Format.SQLITE,
                                "$table.$column",
                                value,
                                cursorValueType(it, columnIndex),
                                document.canWrite() && rowId != null,
                                Locator.SqlCell(table, rowId, column),
                            )
                        }
                    }
                }
            }
        }
        temp.delete()
        return out to tableCount
    }

    private fun editXml(context: Context, uri: Uri, hit: StateHit, raw: String): StateHit {
        val locator = hit.locator as? Locator.XmlKey ?: error("Некорректный XML locator")
        val text = readText(context, uri)
        val escapedKey = Regex.escape(escapeXml(locator.name))
        var updated: String? = null
        val attrRegex = Regex("""(<\s*(?:boolean|int|long|float)\b[^>]*?\bname\s*=\s*\"$escapedKey\"[^>]*?\bvalue\s*=\s*\")([^\"]*)(\"[^>]*/\s*>)""", RegexOption.IGNORE_CASE)
        val attrMatch = attrRegex.find(text)
        if (attrMatch != null) {
            val coerced = coerceText(raw, hit.valueType)
            val replacement = attrMatch.groupValues[1] + escapeXml(coerced) + attrMatch.groupValues[3]
            updated = text.replaceRange(attrMatch.range, replacement)
        }
        if (updated == null) {
            val stringRegex = Regex("""(<\s*string\b[^>]*?\bname\s*=\s*\"$escapedKey\"[^>]*>)(.*?)(<\s*/\s*string\s*>)""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            val stringMatch = requireNotNull(stringRegex.find(text)) { "Ключ ${locator.name} не найден при сохранении" }
            val replacement = stringMatch.groupValues[1] + escapeXml(raw) + stringMatch.groupValues[3]
            updated = text.replaceRange(stringMatch.range, replacement)
        }
        writeText(context, uri, requireNotNull(updated))
        return hit.copy(value = coerceText(raw, hit.valueType))
    }

    private fun editJson(context: Context, uri: Uri, hit: StateHit, raw: String): StateHit {
        val locator = hit.locator as? Locator.JsonPath ?: error("Некорректный JSON locator")
        val text = readText(context, uri).trim()
        val root: Any = if (text.startsWith("{")) JSONObject(text) else JSONArray(text)
        val replacement = coerceJson(raw, hit.valueType)
        setJsonValue(root, locator.segments, replacement)
        val rendered = when (root) {
            is JSONObject -> root.toString(2)
            is JSONArray -> root.toString(2)
            else -> error("Некорректный JSON root")
        }
        writeText(context, uri, rendered)
        return hit.copy(value = if (replacement === JSONObject.NULL) "null" else replacement.toString(), valueType = valueType(replacement))
    }

    private fun editTextLine(context: Context, uri: Uri, hit: StateHit, raw: String): StateHit {
        val locator = hit.locator as? Locator.TextLine ?: error("Некорректный text locator")
        val text = readText(context, uri)
        val lines = text.split('\n').toMutableList()
        val index = locator.lineNumber - 1
        require(index in lines.indices) { "Строка ${locator.lineNumber} больше не существует" }
        val newValue = coerceText(raw, hit.valueType)
        lines[index] = if (locator.separator == null) newValue else "${hit.key}${locator.separator}$newValue"
        writeText(context, uri, lines.joinToString("\n"))
        return hit.copy(value = newValue)
    }

    private fun editSqlite(context: Context, uri: Uri, hit: StateHit, raw: String): StateHit {
        val locator = hit.locator as? Locator.SqlCell ?: error("Некорректный SQLite locator")
        val rowId = requireNotNull(locator.rowId) { "Эта SQLite-строка не имеет rowid и доступна только для просмотра" }
        val temp = copyToTemp(context, uri, "edit-${sha256(uri.toString()).take(16)}.db")
        val value = coerceSql(raw, hit.valueType)
        SQLiteDatabase.openDatabase(temp.absolutePath, null, SQLiteDatabase.OPEN_READWRITE).use { db ->
            val cv = ContentValues()
            when (value) {
                null -> cv.putNull(locator.column)
                is Int -> cv.put(locator.column, value)
                is Long -> cv.put(locator.column, value)
                is Float -> cv.put(locator.column, value)
                is Double -> cv.put(locator.column, value)
                is Boolean -> cv.put(locator.column, if (value) 1 else 0)
                else -> cv.put(locator.column, value.toString())
            }
            val updated = db.update(locator.table, cv, "rowid=?", arrayOf(rowId.toString()))
            require(updated == 1) { "SQLite update изменил $updated строк вместо одной" }
        }
        context.contentResolver.openOutputStream(uri, "wt").use { output ->
            requireNotNull(output) { "Не удалось записать SQLite-файл" }
            temp.inputStream().buffered(COPY_BUFFER).use { input -> input.copyTo(output, COPY_BUFFER) }
            output.flush()
        }
        temp.delete()
        return hit.copy(value = value?.toString() ?: "null")
    }

    private fun setJsonValue(root: Any, segments: List<String>, replacement: Any) {
        require(segments.isNotEmpty()) { "Нельзя заменить JSON root целиком из этого редактора" }
        var current: Any = root
        for (i in 0 until segments.lastIndex) {
            val segment = segments[i]
            current = when {
                segment.startsWith("o:") -> (current as JSONObject).get(segment.removePrefix("o:"))
                segment.startsWith("a:") -> (current as JSONArray).get(segment.removePrefix("a:").toInt())
                else -> error("Некорректный JSON path")
            }
        }
        val last = segments.last()
        when {
            last.startsWith("o:") -> (current as JSONObject).put(last.removePrefix("o:"), replacement)
            last.startsWith("a:") -> (current as JSONArray).put(last.removePrefix("a:").toInt(), replacement)
            else -> error("Некорректный JSON path")
        }
    }

    private fun detectFormat(name: String): Format? {
        val lower = name.lowercase(Locale.ROOT)
        return when {
            lower.endsWith(".db") || lower.endsWith(".sqlite") || lower.endsWith(".sqlite3") -> Format.SQLITE
            lower.endsWith(".json") -> Format.JSON
            lower.endsWith(".properties") || lower.endsWith(".ini") || lower.endsWith(".cfg") || lower.endsWith(".conf") -> Format.PROPERTIES
            lower.endsWith(".xml") -> Format.SHARED_PREFS_XML
            lower.endsWith(".txt") || lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".csv") || lower.endsWith(".toml") || lower.endsWith(".sav") -> Format.TEXT
            else -> null
        }
    }

    private fun hit(
        uri: Uri,
        path: String,
        format: Format,
        key: String,
        value: String,
        valueType: ValueType,
        writable: Boolean,
        locator: Locator,
    ): StateHit {
        val idBase = "$uri|$format|$key|$locator"
        return StateHit(sha256(idBase), uri.toString(), path, format, key, value, valueType, writable, locator)
    }

    private fun matches(query: String, key: String, value: String): Boolean =
        query == "*" || key.contains(query, ignoreCase = true) || value.contains(query, ignoreCase = true)

    private fun inferStringType(value: String): ValueType = when {
        value.equals("true", true) || value.equals("false", true) -> ValueType.BOOLEAN
        value.toIntOrNull() != null -> ValueType.INTEGER
        value.toLongOrNull() != null -> ValueType.LONG
        value.toDoubleOrNull() != null -> ValueType.FLOAT
        value.equals("null", true) -> ValueType.NULL
        else -> ValueType.STRING
    }

    private fun valueType(value: Any): ValueType = when (value) {
        JSONObject.NULL -> ValueType.NULL
        is Boolean -> ValueType.BOOLEAN
        is Int -> ValueType.INTEGER
        is Long -> ValueType.LONG
        is Float, is Double -> ValueType.FLOAT
        is String -> ValueType.STRING
        else -> ValueType.OTHER
    }

    private fun cursorValueType(cursor: Cursor, index: Int): ValueType = when (cursor.getType(index)) {
        Cursor.FIELD_TYPE_INTEGER -> ValueType.LONG
        Cursor.FIELD_TYPE_FLOAT -> ValueType.FLOAT
        Cursor.FIELD_TYPE_STRING -> inferStringType(cursor.getString(index))
        Cursor.FIELD_TYPE_NULL -> ValueType.NULL
        else -> ValueType.OTHER
    }

    private fun cursorValue(cursor: Cursor, index: Int): String? = when (cursor.getType(index)) {
        Cursor.FIELD_TYPE_INTEGER -> cursor.getLong(index).toString()
        Cursor.FIELD_TYPE_FLOAT -> cursor.getDouble(index).toString()
        Cursor.FIELD_TYPE_STRING -> cursor.getString(index)
        Cursor.FIELD_TYPE_NULL -> "null"
        else -> null
    }

    private fun coerceText(raw: String, type: ValueType): String = when (type) {
        ValueType.BOOLEAN -> raw.trim().lowercase(Locale.ROOT).also { require(it == "true" || it == "false") { "Ожидается true или false" } }
        ValueType.INTEGER -> raw.trim().also { require(it.toIntOrNull() != null) { "Ожидается Int" } }
        ValueType.LONG -> raw.trim().also { require(it.toLongOrNull() != null) { "Ожидается Long" } }
        ValueType.FLOAT -> raw.trim().also { require(it.toDoubleOrNull() != null) { "Ожидается число" } }
        ValueType.NULL -> if (raw.trim().equals("null", true)) "null" else raw
        else -> raw
    }

    private fun coerceJson(raw: String, type: ValueType): Any = when (type) {
        ValueType.BOOLEAN -> raw.trim().lowercase(Locale.ROOT).let { require(it == "true" || it == "false"); it == "true" }
        ValueType.INTEGER -> requireNotNull(raw.trim().toIntOrNull()) { "Ожидается Int" }
        ValueType.LONG -> requireNotNull(raw.trim().toLongOrNull()) { "Ожидается Long" }
        ValueType.FLOAT -> requireNotNull(raw.trim().toDoubleOrNull()) { "Ожидается число" }
        ValueType.NULL -> if (raw.trim().equals("null", true)) JSONObject.NULL else raw
        else -> raw
    }

    private fun coerceSql(raw: String, type: ValueType): Any? = when (type) {
        ValueType.BOOLEAN -> raw.trim().lowercase(Locale.ROOT).let { require(it == "true" || it == "false" || it == "1" || it == "0"); it == "true" || it == "1" }
        ValueType.INTEGER -> requireNotNull(raw.trim().toIntOrNull()) { "Ожидается Int" }
        ValueType.LONG -> requireNotNull(raw.trim().toLongOrNull()) { "Ожидается Long" }
        ValueType.FLOAT -> requireNotNull(raw.trim().toDoubleOrNull()) { "Ожидается число" }
        ValueType.NULL -> null
        else -> raw
    }

    private fun readText(context: Context, uri: Uri): String =
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Не удалось открыть файл" }
            input.bufferedReader(Charsets.UTF_8).use { it.readText() }
        }

    private fun writeText(context: Context, uri: Uri, text: String) {
        context.contentResolver.openOutputStream(uri, "wt").use { output ->
            requireNotNull(output) { "Не удалось открыть файл для записи" }
            output.writer(Charsets.UTF_8).use { writer -> writer.write(text); writer.flush() }
        }
    }

    private fun ensureBackup(context: Context, uri: Uri) {
        val file = backupFile(context, uri)
        if (file.isFile) return
        file.parentFile?.mkdirs()
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Не удалось прочитать исходник для backup" }
            file.outputStream().buffered(COPY_BUFFER).use { output -> input.copyTo(output, COPY_BUFFER) }
        }
        require(file.isFile && file.length() > 0L) { "Не удалось создать backup" }
    }

    private fun backupFile(context: Context, uri: Uri): File =
        File(context.cacheDir, "runtime-state-backups/${sha256(uri.toString())}.bak")

    private fun copyToTemp(context: Context, uri: Uri, name: String): File {
        val file = File(context.cacheDir, "runtime-state-temp/$name").apply { parentFile?.mkdirs(); delete() }
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Не удалось открыть SQLite-файл" }
            file.outputStream().buffered(COPY_BUFFER).use { output -> input.copyTo(output, COPY_BUFFER) }
        }
        require(file.length() > 0L) { "SQLite-файл пуст" }
        return file
    }

    private fun quoteIdent(value: String): String = "\"" + value.replace("\"", "\"\"") + "\""
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun escapeXml(value: String): String = value
        .replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    private fun unescapeXml(value: String): String = value
        .replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")

    private const val COPY_BUFFER = 128 * 1024
}
