package org.unirevlab.security.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.data.AuditJobRepository
import org.unirevlab.security.model.AuditJobSummary
import org.unirevlab.security.model.AuditStage
import org.unirevlab.security.model.PersistedAuditState

@Composable
fun AutoAuditScreen(
    language: AppLanguage,
    state: PersistedAuditState?,
    summary: AuditJobSummary?,
    isRunning: Boolean,
    error: String?,
    onLanguageChanged: (AppLanguage) -> Unit,
    onPickInstalled: () -> Unit,
    onPickFile: () -> Unit,
    onCancel: () -> Unit,
    onOpenAiChat: () -> Unit,
    onExport: (String) -> Unit,
) {
    Surface(Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 18.dp, vertical = 22.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Eyebrow("UNIREVLAB · AUTO AUDIT 0.45")
                        Text(language.text("Аудит в один выбор", "One-selection audit"), style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)
                    }
                    LanguageSelector(language, enabled = !isRunning, onLanguageChanged)
                }
            }
            if (error != null) {
                item { ErrorCard(error) }
            }
            item {
                TargetPickerCard(
                    language = language,
                    enabled = !isRunning,
                    onPickInstalled = onPickInstalled,
                    onPickFile = onPickFile,
                )
            }
            if (state != null) {
                item { ProgressCard(language, state, isRunning, onCancel) }
            }
            if (summary != null && state?.stage == AuditStage.COMPLETE) {
                item { ResultCard(language, summary) }
                item { OutputCard(language, summary.outputFiles.toSet(), onExport) }
            }
            item { AiReportChatCard(language = language, isRunning = isRunning, onOpen = onOpenAiChat) }
            item {
                MethodBoundaryCard(language)
                Spacer(Modifier.height(12.dp))
            }
        }
    }
}

@Composable
private fun AiReportChatCard(language: AppLanguage, isRunning: Boolean, onOpen: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = .55f)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Eyebrow("AI · OPENROUTER")
            Text(language.text("Чат по полному отчёту", "Full-report AI chat"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                language.text(
                    "Откройте текущий полный отчёт или импортируйте ранее скачанный отчёт / подписанный пакет. Список бесплатных моделей загружается автоматически.",
                    "Open the current full report or import a previously saved report / signed package. Free models are loaded automatically.",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = onOpen, enabled = !isRunning, modifier = Modifier.fillMaxWidth()) {
                Text(language.text("Открыть AI-чат", "Open AI chat"))
            }
        }
    }
}

@Composable
private fun TargetPickerCard(language: AppLanguage, enabled: Boolean, onPickInstalled: () -> Unit, onPickFile: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(language.text("Новая цель", "New target"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Button(
            onClick = onPickInstalled,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth().height(56.dp),
        ) { Text(language.text("Выбрать установленное приложение", "Select installed application")) }
        OutlinedButton(
            onClick = onPickFile,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) { Text(language.text("Открыть APK / архив", "Open APK / archive")) }
        Text(
            language.text(
                "Дальше процесс идёт в фоне: APK-набор → DEX/native/runtime → настоящий IL2CPP dump по всем ABI → подтверждённые офсеты → отчёт → подпись.",
                "The rest runs in background: APK set → DEX/native/runtime → real IL2CPP dump for every ABI → confirmed offsets → report → signature.",
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ProgressCard(language: AppLanguage, state: PersistedAuditState, running: Boolean, onCancel: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = .55f)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(state.stage.localizedTitle(language), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(state.message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text("${state.progress}%", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
            }
            LinearProgressIndicator(
                progress = { state.progress / 100f },
                modifier = Modifier.fillMaxWidth().height(6.dp),
            )
            StageRail(language, state.stage)
            state.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            if (running) {
                val cancellationRequested = state.stage == AuditStage.CANCELLING
                OutlinedButton(
                    onClick = onCancel,
                    enabled = !cancellationRequested,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (cancellationRequested) language.text("Остановка запрошена…", "Stopping…") else language.text("Остановить", "Stop")) }
            }
        }
    }
}

@Composable
private fun StageRail(language: AppLanguage, current: AuditStage) {
    val stages = listOf(
        AuditStage.ARCHIVE,
        AuditStage.MANIFEST,
        AuditStage.DEX,
        AuditStage.NATIVE,
        AuditStage.IL2CPP,
        AuditStage.SUPPLY_CHAIN,
        AuditStage.GRADLE_MODULES,
        AuditStage.ARTIFACTS,
        AuditStage.SIGNING,
    )
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        stages.forEach { stage ->
            val done = current == AuditStage.COMPLETE || current.defaultProgress > stage.defaultProgress
            val active = current == stage
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp)) {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        shape = RoundedCornerShape(50),
                        color = when {
                            done -> MaterialTheme.colorScheme.primary
                            active -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.outline.copy(alpha = .4f)
                        },
                    ) {}
                }
                Text(
                    stage.localizedTitle(language),
                    modifier = Modifier.padding(start = 9.dp),
                    style = MaterialTheme.typography.labelMedium,
                    color = if (active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ResultCard(language: AppLanguage, summary: AuditJobSummary) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF102A22)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Eyebrow(language.text("АНАЛИЗ ЗАВЕРШЁН", "ANALYSIS COMPLETE"))
            Text(summary.displayName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            summary.packageName?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Metric(language.text("Находки", "Findings"), summary.findings.toString())
                Metric(language.text("Критичные", "Critical"), summary.critical.toString())
                Metric(language.text("Высокие", "High"), summary.high.toString())
                Metric(language.text("DEX-методы", "DEX methods"), summary.dexMethods.toString())
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = .3f))
            Text(
                language.text(
                    "Native: ${summary.nativeLibraries} · IL2CPP: ${if (summary.il2cppDetected) "обнаружен" else "не обнаружен"} · Артефактов: ${summary.exportedArtifactCount}",
                    "Native: ${summary.nativeLibraries} · IL2CPP: ${if (summary.il2cppDetected) "detected" else "not detected"} · Artifacts: ${summary.exportedArtifactCount}",
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            if (summary.il2cppDetected || summary.il2cppDumpStatus != null) {
                Text(
                    buildString {
                        append(language.text("Rodroid dump: ", "Rodroid dump: "))
                        append(summary.il2cppDumpStatus ?: language.text("не запускался", "not run"))
                        summary.il2cppMetadataVersion?.let { append(" · metadata v$it") }
                        if (summary.il2cppSuccessfulAbis.isNotEmpty()) append(" · ${summary.il2cppSuccessfulAbis.joinToString()}")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (summary.il2cppDumpStatus == "COMPLETE") MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
                )
                summary.il2cppDumpError?.takeIf(String::isNotBlank)?.let {
                    Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
                }
                if (summary.il2cppDumpStatus == "COMPLETE") {
                    Text(
                        language.text(
                            "Подтверждённые поверхности: игровые ${summary.confirmedGameplaySurfaces}, приложения/монетизация ${summary.confirmedApplicationSurfaces}",
                            "Confirmed surfaces: gameplay ${summary.confirmedGameplaySurfaces}, application/monetization ${summary.confirmedApplicationSurfaces}",
                        ),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            Text("SHA-256 ${summary.artifactSha256.take(16)}…", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun OutputCard(language: AppLanguage, availableFiles: Set<String>, onExport: (String) -> Unit) {
    val outputs = listOf(
        AuditJobRepository.SIGNED_EVIDENCE_PACKAGE to (language.text("Пакет заказчику", "Customer package") to language.text("Все результаты + подпись", "All results + signature")),
        AuditJobRepository.CUSTOMER_REPORT to (language.text("Отчёт .md", "Report .md") to language.text("Что найдено и как исправить", "Findings and remediation")),
        AuditJobRepository.OFFSET_READABLE to (language.text("Офсеты — понятный отчёт", "Offsets — readable report") to language.text("HTML: поиск, фильтры, имена и пояснения", "HTML: search, filters, names and explanations")),
        AuditJobRepository.OFFSET_EVIDENCE to (language.text("Офсеты JSON", "Offsets JSON") to language.text("Технические RVA, metadata offsets и tokens", "Technical RVA, metadata offsets and tokens")),
        AuditJobRepository.IL2CPP_DUMP to ("IL2CPP dump" to language.text("Типы, поля и методы из настоящего dump", "Types, fields and methods from the real dump")),
        AuditJobRepository.IL2CPP_DUMP_PACKAGE to (language.text("Полный IL2CPP-пакет", "Complete IL2CPP package") to language.text("Все ABI, script, строки, headers и индексы", "All ABIs, script, strings, headers and indexes")),
        AuditJobRepository.GRADLE_MODULE_EVIDENCE to (language.text("Gradle-модули", "Gradle modules") to language.text("Base, split, dynamic-feature и build metadata", "Base, split, dynamic-feature and build metadata")),
        AuditJobRepository.VERIFICATION_PLAN to (language.text("План проверок", "Verification plan") to language.text("Безопасные тесты сборки владельца", "Safe owner-build tests")),
        AuditJobRepository.REPORT_JSON to (language.text("Полный JSON", "Full JSON") to language.text("Все доказательства и находки", "All evidence and findings")),
        AuditJobRepository.ARTIFACT_BUNDLE to (language.text("Артефакты", "Artifacts") to "DEX, ELF, metadata, runtime"),
    )
    Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text(language.text("Результаты", "Results"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        outputs.forEach { (file, labels) ->
            val available = file in availableFiles
            OutlinedCard(
                Modifier.fillMaxWidth().clickable(enabled = available) { onExport(file) },
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = .45f)),
            ) {
                Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(labels.first, fontWeight = FontWeight.SemiBold)
                        Text(labels.second, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Text(
                        if (available) language.text("Экспорт", "Export") else language.text("Не создан", "Not created"),
                        color = if (available) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
            }
        }
    }
}

@Composable
private fun MethodBoundaryCard(language: AppLanguage) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(language.text("Что делает автоматизация", "What automation does"), fontWeight = FontWeight.SemiBold)
            Text(
                language.text(
                    "Пассивно извлекает и анализирует артефакты, десериализует IL2CPP metadata настоящим Rodroid-движком, строит dumps и подтверждённые offsets/evidence. Целевой APK не запускается.",
                    "Passively extracts and analyzes artifacts, deserializes IL2CPP metadata with the real Rodroid engine, and builds dumps plus confirmed offsets/evidence. The target APK is not executed.",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                language.text(
                    "Обфусцированные исходные имена не выдумываются: семантические метки и гипотезы экспортируются отдельно от подтверждённых данных.",
                    "Obfuscated original names are never invented: semantic labels and hypotheses are exported separately from confirmed data.",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
    }
}

@Composable
private fun ErrorCard(error: String) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
        Text(error, modifier = Modifier.fillMaxWidth().padding(14.dp), color = MaterialTheme.colorScheme.onErrorContainer)
    }
}

@Composable
private fun Metric(label: String, value: String) {
    Column {
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun Eyebrow(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.Bold,
    )
}

@Composable
private fun LanguageSelector(language: AppLanguage, enabled: Boolean, onChanged: (AppLanguage) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        if (language == AppLanguage.RUSSIAN) {
            Button(onClick = {}, enabled = enabled) { Text("RU") }
            OutlinedButton(onClick = { onChanged(AppLanguage.ENGLISH) }, enabled = enabled) { Text("EN") }
        } else {
            OutlinedButton(onClick = { onChanged(AppLanguage.RUSSIAN) }, enabled = enabled) { Text("RU") }
            Button(onClick = {}, enabled = enabled) { Text("EN") }
        }
    }
}

private fun AuditStage.localizedTitle(language: AppLanguage): String = language.text(
    title,
    when (this) {
        AuditStage.QUEUED -> "Queued"
        AuditStage.PREPARING -> "Preparing input"
        AuditStage.ARCHIVE -> "APK structure and signature"
        AuditStage.MANIFEST -> "Manifest and resources"
        AuditStage.DEX -> "DEX calls and trust surfaces"
        AuditStage.NATIVE -> "Native ELF and JNI"
        AuditStage.IL2CPP -> "IL2CPP and runtime metadata"
        AuditStage.SUPPLY_CHAIN -> "Components and dependencies"
        AuditStage.GRADLE_MODULES -> "Gradle and application modules"
        AuditStage.REPORT -> "Report and recommendations"
        AuditStage.ARTIFACTS -> "Artifacts and confirmed RVA"
        AuditStage.SIGNING -> "Evidence package signature"
        AuditStage.COMPLETE -> "Complete"
        AuditStage.CANCELLING -> "Stopping analysis"
        AuditStage.CANCELLED -> "Cancelled"
        AuditStage.FAILED -> "Failed"
    },
)
