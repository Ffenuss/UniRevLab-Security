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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.data.AuditJobRepository
import org.unirevlab.security.model.AuditJobSummary
import org.unirevlab.security.model.AuditProfile
import org.unirevlab.security.model.AuditStage
import org.unirevlab.security.model.PersistedAuditState

@Composable
fun AuditProfileScreen(
    initial: AuditProfile?,
    onSave: (AuditProfile) -> Unit,
) {
    var project by remember(initial) { mutableStateOf(initial?.projectName.orEmpty()) }
    var organization by remember(initial) { mutableStateOf(initial?.organization.orEmpty()) }
    var purpose by remember(initial) { mutableStateOf(initial?.purpose ?: "Авторизованный аудит безопасности Android-приложения") }
    var dynamic by remember(initial) { mutableStateOf(initial?.dynamicAnalysis ?: false) }
    var network by remember(initial) { mutableStateOf(initial?.networkTesting ?: false) }
    val profile = AuditProfile(
        projectName = project,
        organization = organization,
        purpose = purpose,
        dynamicAnalysis = dynamic,
        networkTesting = network,
    )

    Surface(Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 20.dp, vertical = 28.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                Eyebrow("НАСТРОЙКА · ОДИН РАЗ")
                Text("Профиль аудита", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.SemiBold)
                Text(
                    "Эти данные попадут во все отчёты. После сохранения для нового задания потребуется только выбрать приложение.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            item {
                OutlinedTextField(
                    value = project,
                    onValueChange = { project = it.take(160) },
                    label = { Text("Проект") },
                    placeholder = { Text("Например, Mobile Security Review") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item {
                OutlinedTextField(
                    value = organization,
                    onValueChange = { organization = it.take(160) },
                    label = { Text("Заказчик / владелец") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item {
                OutlinedTextField(
                    value = purpose,
                    onValueChange = { purpose = it.take(500) },
                    label = { Text("Цель и основание") },
                    minLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item {
                ProfileToggle("Динамические проверки разрешены контрактом", dynamic) { dynamic = it }
                ProfileToggle("Сетевые проверки разрешены контрактом", network) { network = it }
            }
            item {
                Button(
                    onClick = { onSave(profile) },
                    enabled = profile.isValid,
                    modifier = Modifier.fillMaxWidth().height(54.dp),
                ) { Text("Сохранить профиль") }
            }
        }
    }
}

@Composable
fun AutoAuditScreen(
    profile: AuditProfile,
    authorityConfirmed: Boolean,
    state: PersistedAuditState?,
    summary: AuditJobSummary?,
    isRunning: Boolean,
    error: String?,
    onAuthorityChanged: (Boolean) -> Unit,
    onPickInstalled: () -> Unit,
    onPickFile: () -> Unit,
    onCancel: () -> Unit,
    onEditProfile: () -> Unit,
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
                        Eyebrow("UNIREVLAB · AUTO AUDIT 0.42.1")
                        Text("Аудит в один выбор", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)
                    }
                    OutlinedButton(onClick = onEditProfile, enabled = !isRunning) { Text("Профиль") }
                }
            }
            item {
                ProfileCard(profile)
            }
            if (error != null) {
                item { ErrorCard(error) }
            }
            item {
                AuthorityCard(authorityConfirmed, isRunning, onAuthorityChanged)
            }
            item {
                TargetPickerCard(
                    enabled = authorityConfirmed && !isRunning,
                    onPickInstalled = onPickInstalled,
                    onPickFile = onPickFile,
                )
            }
            if (state != null) {
                item { ProgressCard(state, isRunning, onCancel) }
            }
            if (summary != null && state?.stage == AuditStage.COMPLETE) {
                item { ResultCard(summary) }
                item { OutputCard(onExport) }
            }
            item { AiReportChatCard(isRunning = isRunning, onOpen = onOpenAiChat) }
            item {
                MethodBoundaryCard()
                Spacer(Modifier.height(12.dp))
            }
        }
    }
}

@Composable
private fun AiReportChatCard(isRunning: Boolean, onOpen: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = .55f)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Eyebrow("AI · OPENROUTER")
            Text("Чат по полному отчёту", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                "Откройте текущий full-report.json или импортируйте ранее скачанный отчёт / подписанный пакет. Список бесплатных моделей загружается автоматически.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = onOpen, enabled = !isRunning, modifier = Modifier.fillMaxWidth()) {
                Text("Открыть AI-чат")
            }
        }
    }
}

@Composable
private fun ProfileCard(profile: AuditProfile) {
    OutlinedCard(Modifier.fillMaxWidth(), border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = .45f))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(profile.projectName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(profile.organization, color = MaterialTheme.colorScheme.secondary)
            Text(profile.purpose, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun AuthorityCard(checked: Boolean, locked: Boolean, onChanged: (Boolean) -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = .55f)),
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = checked, onCheckedChange = onChanged, enabled = !locked)
            Column(Modifier.padding(start = 8.dp)) {
                Text("Scope подтверждён", fontWeight = FontWeight.SemiBold)
                Text(
                    "Я владелец цели или имею явное разрешение заказчика на выбранные виды анализа.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun TargetPickerCard(enabled: Boolean, onPickInstalled: () -> Unit, onPickFile: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Новая цель", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Button(
            onClick = onPickInstalled,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth().height(56.dp),
        ) { Text("Выбрать установленное приложение") }
        OutlinedButton(
            onClick = onPickFile,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) { Text("Открыть APK / архив") }
        Text(
            "Дальше процесс идёт в фоне: APK-набор → DEX/native/runtime → offsets → отчёт → подпись.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ProgressCard(state: PersistedAuditState, running: Boolean, onCancel: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = .55f)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(state.stage.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(state.message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text("${state.progress}%", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
            }
            LinearProgressIndicator(
                progress = { state.progress / 100f },
                modifier = Modifier.fillMaxWidth().height(6.dp),
            )
            StageRail(state.stage)
            state.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            if (running) {
                val cancellationRequested = state.stage == AuditStage.CANCELLING
                OutlinedButton(
                    onClick = onCancel,
                    enabled = !cancellationRequested,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (cancellationRequested) "Остановка запрошена…" else "Остановить") }
            }
        }
    }
}

@Composable
private fun StageRail(current: AuditStage) {
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
                    stage.title,
                    modifier = Modifier.padding(start = 9.dp),
                    style = MaterialTheme.typography.labelMedium,
                    color = if (active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ResultCard(summary: AuditJobSummary) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF102A22)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Eyebrow("АНАЛИЗ ЗАВЕРШЁН")
            Text(summary.displayName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            summary.packageName?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Metric("Findings", summary.findings.toString())
                Metric("Critical", summary.critical.toString())
                Metric("High", summary.high.toString())
                Metric("DEX methods", summary.dexMethods.toString())
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = .3f))
            Text(
                "Native: ${summary.nativeLibraries} · IL2CPP: ${if (summary.il2cppDetected) "да, metadata ${summary.il2cppMetadataVersion ?: "?"}" else "нет"} · Артефактов: ${summary.exportedArtifactCount}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text("SHA-256 ${summary.artifactSha256.take(16)}…", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun OutputCard(onExport: (String) -> Unit) {
    val outputs = listOf(
        AuditJobRepository.SIGNED_EVIDENCE_PACKAGE to ("Пакет заказчику" to "Все результаты + подпись"),
        AuditJobRepository.CUSTOMER_REPORT to ("Отчёт .md" to "Что найдено и как исправить"),
        AuditJobRepository.OFFSET_READABLE to ("Офсеты — понятный отчёт" to "HTML: поиск, фильтры, имена и пояснения"),
        AuditJobRepository.OFFSET_EVIDENCE to ("Офсеты JSON" to "Технические RVA, metadata offsets и tokens"),
        AuditJobRepository.IL2CPP_DUMP to ("IL2CPP dump" to "Восстановленные types, fields, methods"),
        AuditJobRepository.GRADLE_MODULE_EVIDENCE to ("Gradle-модули" to "Base, split, dynamic-feature и build metadata"),
        AuditJobRepository.VERIFICATION_PLAN to ("План проверок" to "Безопасные тесты owner-build"),
        AuditJobRepository.REPORT_JSON to ("Полный JSON" to "Все evidence и findings"),
        AuditJobRepository.ARTIFACT_BUNDLE to ("Артефакты" to "DEX, ELF, metadata, runtime"),
    )
    Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text("Результаты", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        outputs.forEach { (file, labels) ->
            OutlinedCard(
                Modifier.fillMaxWidth().clickable { onExport(file) },
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = .45f)),
            ) {
                Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(labels.first, fontWeight = FontWeight.SemiBold)
                        Text(labels.second, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Text("Экспорт", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge)
                }
            }
        }
    }
}

@Composable
private fun MethodBoundaryCard() {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Что делает автоматизация", fontWeight = FontWeight.SemiBold)
            Text(
                "Пассивно извлекает и анализирует артефакты, готовит воспроизводимые offsets/evidence и полный remediation-отчёт. Целевой APK не запускается и не перепаковывается.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Активная проверка выполняется по verification-plan в отдельной тестовой сборке владельца, подписанной его ключом.",
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
private fun ProfileToggle(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Switch(checked = checked, onCheckedChange = onChecked)
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
