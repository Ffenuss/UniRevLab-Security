package org.unirevlab.security.analysis

import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/** Publishes job-level offset exports exclusively from completed Rodroid dump output. */
object ConfirmedDumpOutputExporter {
    fun write(
        result: RealIl2CppDumpEngine.Result?,
        dumpDirectory: File,
        jsonDestination: File,
        htmlDestination: File,
        languageCode: String,
    ) {
        val aggregate = File(dumpDirectory, "confirmed-offsets-all-abi.json")
        val json = if (result?.complete == true && aggregate.isFile) {
            JSONObject(aggregate.readText(Charsets.UTF_8))
                .put("status", "COMPLETE")
                .put("engine", result.engine ?: "il2cpp-dumper-rs")
                .put("engineRevision", result.engineRevision ?: JSONObject.NULL)
                .put("successfulAbis", JSONArray(result.successfulAbis))
                .put("failedAbis", JSONArray(result.failedAbis))
        } else {
            JSONObject()
                .put("schemaVersion", "2.0")
                .put("status", "NOT_AVAILABLE")
                .put("error", result?.error ?: if (languageCode == "en") "A matching global-metadata.dat/libil2cpp.so pair was not found" else "Не найдена совместимая пара global-metadata.dat/libil2cpp.so")
                .put("source", "real Rodroid dump only")
                .put("gameplayOffsets", JSONArray())
                .put("applicationAndMonetizationOffsets", JSONArray())
        }
        jsonDestination.writeText(json.toString(2), Charsets.UTF_8)
        writeHtml(json, htmlDestination, languageCode)
    }

    private fun writeHtml(json: JSONObject, destination: File, languageCode: String) {
        val ru = languageCode != "en"
        val gameplay = json.optJSONArray("gameplayOffsets") ?: JSONArray()
        val application = json.optJSONArray("applicationAndMonetizationOffsets") ?: JSONArray()
        val rows = buildList {
            for (array in listOf(gameplay, application)) {
                for (index in 0 until array.length()) array.optJSONObject(index)?.let(::add)
            }
        }
        destination.bufferedWriter(Charsets.UTF_8).use { output ->
            output.appendLine("<!doctype html><html lang=\"${if (ru) "ru" else "en"}\"><head><meta charset=\"utf-8\">")
            output.appendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>IL2CPP confirmed offsets</title>")
            output.appendLine("<style>body{font:15px system-ui;background:#0d1421;color:#e8edf8;margin:0;padding:20px}main{max-width:1500px;margin:auto}input{width:100%;box-sizing:border-box;padding:13px;background:#151f31;color:#fff;border:1px solid #506078;border-radius:10px;margin:12px 0}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #28364b;vertical-align:top}th{position:sticky;top:0;background:#111b2b}.ok{color:#65d6a6}.bad{color:#ff8e8e}.tag{color:#a98aff}code{color:#71d5ee}small{color:#aab5c8}</style></head><body><main>")
            output.appendLine("<h1>${if (ru) "Подтверждённые IL2CPP-офсеты" else "Confirmed IL2CPP offsets"}</h1>")
            val complete = json.optString("status") == "COMPLETE"
            output.appendLine("<p class=\"${if (complete) "ok" else "bad"}\">${html(if (ru) "Статус: ${json.optString("status")}" else "Status: ${json.optString("status")}")}</p>")
            if (!complete) output.appendLine("<p>${html(json.optString("error"))}</p>")
            output.appendLine("<p><small>${if (ru) "Источник: только успешно завершённый Rodroid dump. Для метода показана формула moduleBase + RVA, для поля — objectAddress + FIELD_OFFSET. Постоянного абсолютного адреса нет из-за ASLR и динамических экземпляров объектов." else "Source: completed Rodroid dump only. Methods include the moduleBase + RVA formula; fields include objectAddress + FIELD_OFFSET. A stable absolute address cannot exist because of ASLR and dynamic object instances."}</small></p>")
            output.appendLine("<input id=\"q\" placeholder=\"${if (ru) "Поиск по ABI, категории, адресу или имени" else "Search ABI, category, address, or name"}\" oninput=\"f()\">")
            output.appendLine("<p>${if (ru) "Записей" else "Rows"}: <b>${rows.size}</b></p><table><thead><tr><th>ABI</th><th>${if (ru) "Область" else "Domain"}</th><th>${if (ru) "Категория" else "Category"}</th><th>Namespace</th><th>${if (ru) "Класс" else "Class"}</th><th>${if (ru) "Член" else "Member"}</th><th>${if (ru) "Тип" else "Type"}</th><th>${if (ru) "Вид смещения" else "Offset kind"}</th><th>${if (ru) "Смещение" else "Offset"}</th><th>${if (ru) "Формула адреса" else "Address formula"}</th><th>${if (ru) "Что требуется" else "Required runtime value"}</th></tr></thead><tbody id=\"rows\">")
            rows.forEach { item ->
                output.appendLine("<tr><td>${html(item.optString("abi"))}</td><td class=\"tag\">${html(item.optString("domain"))}</td><td>${html(item.optString("category"))}</td><td>${html(item.optString("namespace"))}</td><td>${html(item.optString("className"))}</td><td>${html(item.optString("memberName"))}<br><small>${html(item.optString("managedSignature"))}</small></td><td>${html(item.optString("declaredType"))}</td><td>${html(item.optString("addressKind"))}</td><td><code>${html(item.optString("address"))}</code></td><td><code>${html(item.optString("addressFormula"))}</code></td><td>${html(runtimeRequirement(item.optString("runtimeAddressStatus"), ru))}</td></tr>")
            }
            output.appendLine("</tbody></table><script>function f(){const q=document.getElementById('q').value.toLowerCase();for(const r of document.querySelectorAll('#rows tr'))r.hidden=!r.textContent.toLowerCase().includes(q)}</script></main></body></html>")
        }
    }

    private fun html(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")

    private fun runtimeRequirement(value: String, ru: Boolean): String = when (value) {
        "REQUIRES_RUNTIME_MODULE_BASE" -> if (ru) "База libil2cpp.so при запуске" else "Runtime libil2cpp.so base"
        "REQUIRES_LIVE_OBJECT_INSTANCE" -> if (ru) "Адрес экземпляра объекта" else "Live object instance address"
        else -> value
    }
}
