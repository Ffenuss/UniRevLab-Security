package org.unirevlab.security.analysis

import java.util.Locale
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Human-readable security posture aggregation over the already collected static-analysis index.
 *
 * This intentionally separates "the application appears to perform this check" from
 * "the analysed APK is actually modified/rooted/etc.". A single static APK cannot prove a
 * baseline-diff state, and the target application is never launched by this engine.
 */
object ProtectionPostureEngine {
    enum class Status { PRESENT, NOT_DETECTED, UNKNOWN, NOT_APPLICABLE }

    data class Check(
        val id: String,
        val title: String,
        val status: Status,
        val confidence: String,
        val explanation: String,
        val evidence: List<String> = emptyList(),
    )

    data class Posture(
        val checks: List<Check>,
        val presentCount: Int,
        val notDetectedCount: Int,
        val unknownCount: Int,
        val dexCoverageComplete: Boolean,
    )

    private data class Signal(val label: String, val text: String)

    fun scan(report: StaticAnalysisReport): Posture {
        val dex = report.dex
        val dexCoverageComplete = dex != null && !dex.truncated && dex.parseErrors == 0
        val signals = buildSignals(report)

        fun matching(markers: List<String>, limit: Int = 5): List<String> {
            val lowered = markers.map { it.lowercase(Locale.ROOT) }
            return signals.asSequence()
                .filter { signal ->
                    val text = signal.text.lowercase(Locale.ROOT)
                    lowered.any(text::contains)
                }
                .map { it.label }
                .distinct()
                .take(limit)
                .toList()
        }

        fun staticCheck(
            id: String,
            title: String,
            markers: List<String>,
            explanationPresent: String,
            explanationAbsent: String,
        ): Check {
            val evidence = matching(markers)
            return when {
                evidence.isNotEmpty() -> Check(
                    id = id,
                    title = title,
                    status = Status.PRESENT,
                    confidence = "HIGH",
                    explanation = explanationPresent,
                    evidence = evidence,
                )
                dexCoverageComplete -> Check(
                    id = id,
                    title = title,
                    status = Status.NOT_DETECTED,
                    confidence = "MEDIUM",
                    explanation = explanationAbsent,
                )
                else -> Check(
                    id = id,
                    title = title,
                    status = Status.UNKNOWN,
                    confidence = "LOW",
                    explanation = "Полный DEX-индекс недоступен или был ограничен; отсутствие сигнала нельзя считать доказанным отсутствием проверки.",
                )
            }
        }

        val checks = mutableListOf<Check>()
        checks += staticCheck(
            "ROOT_DETECTION",
            "Проверка root / Magisk / su",
            listOf("rootbeer", "magisk", "/system/xbin/su", "/system/bin/su", "which su", "test-keys", "zygisk", "ro.secure", "ro.debuggable"),
            "В коде обнаружены признаки проверки root/системных артефактов.",
            "Характерные root-detection API/строки в полном статическом DEX-индексе не обнаружены.",
        )
        checks += staticCheck(
            "EMULATOR_DETECTION",
            "Проверка эмулятора",
            listOf("goldfish", "ranchu", "genymotion", "sdk_gphone", "generic_x86", "ro.kernel.qemu", "emulator"),
            "В коде обнаружены признаки определения эмулятора/виртуального устройства.",
            "Характерные emulator-detection сигналы не обнаружены.",
        )
        checks += staticCheck(
            "DEBUGGER_DETECTION",
            "Anti-debug / debugger detection",
            listOf("isdebuggerconnected", "waitingfordebugger", "tracerpid", "ptrace", "debuggerconnected"),
            "В коде есть признаки anti-debug или проверки подключённого отладчика.",
            "Характерные anti-debug/debugger проверки не обнаружены.",
        )
        checks += staticCheck(
            "HOOK_DETECTION",
            "Frida / Xposed / hooking detection",
            listOf("frida", "gum-js-loop", "xposed", "lsposed", "substrate", "zygisk", "frida-server"),
            "В коде обнаружены маркеры anti-hook/Frida/Xposed проверки.",
            "Характерные anti-hook/Frida/Xposed сигналы не обнаружены.",
        )
        checks += staticCheck(
            "SIGNATURE_SELF_CHECK",
            "Проверка собственной подписи",
            listOf("signinginfo", "apkcontentssigners", "signingcertificatehistory", "checksignature", "checksignatures", "signingcertificate"),
            "Приложение обращается к signing/signature API и, вероятно, проверяет собственную подпись или подписи других пакетов.",
            "Явная client-side signature self-check в доступном DEX-коде не обнаружена.",
        )
        checks += staticCheck(
            "APK_SELF_INTEGRITY",
            "Проверка изменения APK / checksum",
            listOf("checksum", "crc32", "apkchecksum", "tampered", "apk integrity", "selfcheck", "self-check", "digest"),
            "Найдены признаки локальной checksum/self-integrity проверки APK или его содержимого.",
            "Явная локальная checksum/self-integrity проверка APK не обнаружена.",
        )
        checks += staticCheck(
            "INSTALL_SOURCE",
            "Проверка источника установки",
            listOf("getinstallsourceinfo", "getinstallerpackagename", "installsourceinfo", "initiatingpackagename", "installingpackagename"),
            "Приложение проверяет installer/install-source metadata.",
            "Проверка источника установки не обнаружена.",
        )
        checks += staticCheck(
            "PLAY_INTEGRITY",
            "Play Integrity / attestation",
            listOf("integritymanager", "standardintegritymanager", "requestintegritytoken", "playintegrity", "meetsdeviceintegrity", "meetsbasicintegrity", "safetynet", "attestation"),
            "Найдены Play Integrity/attestation API или связанные сигналы. Статический анализ не подтверждает серверную валидацию результата.",
            "Play Integrity/attestation API в доступном коде не обнаружены.",
        )

        val network = report.manifest?.networkSecurity
        val pinEvidence = buildList {
            if (network?.pinSetPresent == true) add("Network Security Config: pin-set present")
            addAll(matching(listOf("certificatepinner", "checkservertrusted", "hostnameverifier", "pin-set", "public key pin"), 4))
        }.distinct()
        checks += when {
            pinEvidence.isNotEmpty() -> Check(
                id = "TLS_PINNING",
                title = "TLS certificate/public-key pinning",
                status = Status.PRESENT,
                confidence = "HIGH",
                explanation = "Обнаружена конфигурация или код, связанный с TLS pinning/кастомной проверкой сертификата.",
                evidence = pinEvidence.take(5),
            )
            dexCoverageComplete && network != null -> Check(
                id = "TLS_PINNING",
                title = "TLS certificate/public-key pinning",
                status = Status.NOT_DETECTED,
                confidence = "MEDIUM",
                explanation = "Pin-set и характерные pinning API не обнаружены.",
            )
            else -> Check(
                id = "TLS_PINNING",
                title = "TLS certificate/public-key pinning",
                status = Status.UNKNOWN,
                confidence = "LOW",
                explanation = "Недостаточно данных, чтобы надёжно подтвердить наличие или отсутствие pinning.",
            )
        }

        checks += staticCheck(
            "CLIENT_ENTITLEMENT_GATE",
            "Локальные premium/license/entitlement gates",
            listOf("premium", "entitlement", "licensed", "licensechecker", "billingclient", "querypurchases", "subscription", "subscribed", "ispro", "isvip"),
            "В клиентском коде есть premium/license/billing/entitlement поверхности. Это не означает уязвимость само по себе, но требует проверки trust boundary.",
            "Характерные client-side premium/license/entitlement поверхности не обнаружены.",
        )

        val schemes = report.manifest?.signingSchemes.orEmpty()
        val certs = report.manifest?.signingCertificates.orEmpty()
        checks += when {
            schemes.isNotEmpty() || certs.isNotEmpty() -> Check(
                id = "APK_SIGNATURE_STATE",
                title = "Подпись анализируемого APK",
                status = Status.PRESENT,
                confidence = "CONFIRMED",
                explanation = "Подпись APK распознана. Это подтверждает наличие подписи, но не доказывает, что файл совпадает с эталонной релизной сборкой.",
                evidence = listOf("Schemes: ${schemes.joinToString().ifBlank { "не указаны" }}", "Certificates: ${certs.size}"),
            )
            report.manifest?.signingParseError != null -> Check(
                id = "APK_SIGNATURE_STATE",
                title = "Подпись анализируемого APK",
                status = Status.UNKNOWN,
                confidence = "LOW",
                explanation = "Подпись не удалось разобрать: ${report.manifest.signingParseError}",
            )
            else -> Check(
                id = "APK_SIGNATURE_STATE",
                title = "Подпись анализируемого APK",
                status = Status.UNKNOWN,
                confidence = "LOW",
                explanation = "Данные о подписи отсутствуют.",
            )
        }

        checks += Check(
            id = "BASELINE_TAMPER_STATUS",
            title = "Изменён ли APK относительно оригинала",
            status = Status.UNKNOWN,
            confidence = "N/A",
            explanation = "По одному APK это надёжно не определяется: переподписанный файл может иметь валидную подпись. Для ответа нужен доверенный baseline/предыдущая версия и Version Diff.",
        )

        return Posture(
            checks = checks,
            presentCount = checks.count { it.status == Status.PRESENT },
            notDetectedCount = checks.count { it.status == Status.NOT_DETECTED },
            unknownCount = checks.count { it.status == Status.UNKNOWN },
            dexCoverageComplete = dexCoverageComplete,
        )
    }

    private fun buildSignals(report: StaticAnalysisReport): List<Signal> = buildList {
        report.dex?.methods.orEmpty().take(MAX_SIGNALS_PER_GROUP).forEach {
            val text = "${it.declaringClass}->${it.name}${it.prototype}"
            add(Signal("DEX method: $text", text))
        }
        report.dex?.callXrefs.orEmpty().take(MAX_SIGNALS_PER_GROUP).forEach {
            val text = "${it.callerClass}->${it.callerName} -> ${it.calleeClass}->${it.calleeName}${it.calleePrototype}"
            add(Signal("DEX call: $text", text))
        }
        report.dex?.stringXrefs.orEmpty().take(MAX_SIGNALS_PER_GROUP).forEach {
            val text = "${it.callerClass}->${it.callerName}: ${it.value}"
            add(Signal("DEX string: $text", text))
        }
        report.dex?.typeXrefs.orEmpty().take(MAX_SIGNALS_PER_GROUP).forEach {
            val text = "${it.callerClass}->${it.callerName}: ${it.descriptor}"
            add(Signal("DEX type: $text", text))
        }
        report.findings.take(MAX_SIGNALS_PER_GROUP).forEach { finding ->
            val text = buildString {
                append(finding.id).append(' ').append(finding.title).append(' ')
                append(finding.category).append(' ').append(finding.description).append(' ')
                finding.evidence.take(5).forEach { append(it.location).append(' ').append(it.value).append(' ') }
            }
            add(Signal("Finding: ${finding.id} ${finding.title}", text))
        }
    }

    private const val MAX_SIGNALS_PER_GROUP = 20_000
}
