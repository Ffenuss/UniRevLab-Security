package org.unirevlab.security.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.R

private data class HelpFeature(
    val number: String,
    val title: String,
    val action: String,
    val purpose: String,
    val availability: String,
)

private val helpFeatures = listOf(
    HelpFeature("01", "Файл APK / AAB / APKS / XAPK", "Открывает файл приложения и запускает локальный статический анализ.", "Используйте для APK-файлов, архивов bundle/split и сохранённых копий приложений. APK получает наиболее глубокий локальный анализ; bundle-форматы анализируются в пределах поддерживаемых структур.", "Доступно всегда в активном Assessment."),
    HelpFeature("02", "Установленное приложение", "Показывает список пакетов на устройстве и анализирует base.apk вместе со split APK.", "Подходит, когда APK отдельно скачивать не хочется. Одинаковые DEX/native-объекты переиспользуются по SHA-256, поэтому split-пакеты не должны бессмысленно сканироваться повторно.", "Доступно всегда; список можно фильтровать и обновлять."),
    HelpFeature("03", "RE Browser", "Открывает локальный индекс классов, методов, xref, native и Ghidra-функций.", "Нужен для ручной навигации по уже извлечённым фактам. Тяжёлые индексы строятся вне UI-потока, а поиск ограничивает работу после набора нужного количества результатов.", "После анализа DEX/native; Ghidra-часть появляется после импорта результатов."),
    HelpFeature("04", "Импорт Ghidra result JSON", "Присоединяет результаты headless Ghidra к текущему отчёту.", "Даёт CFG/xref/decompiler/native evidence и улучшает JNI/IL2CPP корреляцию без повторного запуска локального APK.", "После анализа, если в Assessment включён Reverse Engineering."),
    HelpFeature("05", "Импорт advisory feed", "Добавляет локальную/внешнюю базу advisories и повторно коррелирует зависимости.", "Нужен для CVE/advisory-проверки компонентов. Сам APK повторно разбирать не требуется.", "После получения основного отчёта."),
    HelpFeature("06", "Coordinator sync", "Синхронизирует Assessment и нормализованный отчёт с self-hosted coordinator.", "Используется для командной работы, Ghidra worker, истории, audit chain и централизованного хранения результатов.", "После анализа; URL задаётся вручную."),
    HelpFeature("07", "Version diff", "Сравнивает два последовательных анализа одного package.", "Показывает изменения между версиями: findings, зависимости и другие нормализованные факты.", "Автоматически активируется после второго анализа того же приложения."),
    HelpFeature("08", "JSON-отчёт", "Сохраняет детерминированный полный отчёт UniRevLab.", "Это основной машиночитаемый артефакт для повторной проверки, аудита и последующего импорта.", "После анализа."),
    HelpFeature("09", "CycloneDX 1.6", "Экспортирует SBOM в CycloneDX JSON.", "Подходит для dependency inventory, внешних security-процессов и vulnerability management.", "После анализа."),
    HelpFeature("10", "SPDX 3.0.1", "Экспортирует SBOM в SPDX JSON-LD.", "Используется для совместимости с инструментами supply-chain и licence/compliance workflows.", "После анализа."),
)

@Composable
fun HelpScreen(onBack: () -> Unit) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Image(
                    painter = painterResource(R.drawable.unirevlab_logo),
                    contentDescription = "UniRevLab Security",
                    modifier = Modifier.size(72.dp),
                    contentScale = ContentScale.Fit,
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text("Справка и функции", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                    Text("Что делает каждая кнопка и когда её использовать", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }

            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Принцип работы", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("UniRevLab сначала извлекает и нормализует факты, затем использует их в Manifest, DEX, Native, Runtime, SBOM, Findings и RE Browser. Повторно доступные данные переиспользуются, поэтому ускорение не требует отключения анализаторов.")
                }
            }

            helpFeatures.forEach { feature -> FeatureHelpCard(feature) }

            Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Вернуться к анализу") }
        }
    }
}

@Composable
private fun FeatureHelpCard(feature: HelpFeature) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.72f)),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    feature.number,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    fontWeight = FontWeight.Bold,
                )
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text(feature.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(feature.action)
                Text(feature.purpose, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(feature.availability, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
            }
        }
    }
}
