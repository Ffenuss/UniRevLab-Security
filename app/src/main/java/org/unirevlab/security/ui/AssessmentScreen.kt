package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.model.AssessmentScope

@Composable
fun AssessmentScreen(onCreate: (AssessmentScope) -> Unit) {
    var projectName by remember { mutableStateOf("") }
    var organization by remember { mutableStateOf("") }
    var purpose by remember { mutableStateOf("") }
    var authority by remember { mutableStateOf(false) }
    var staticAnalysis by remember { mutableStateOf(true) }
    var reverseEngineering by remember { mutableStateOf(true) }
    var dynamicAnalysis by remember { mutableStateOf(false) }
    var networkTesting by remember { mutableStateOf(false) }

    val scope = AssessmentScope(
        projectName = projectName.trim(),
        organization = organization.trim(),
        purpose = purpose.trim(),
        confirmsAuthority = authority,
        staticAnalysis = staticAnalysis,
        reverseEngineering = reverseEngineering,
        dynamicAnalysis = dynamicAnalysis,
        networkTesting = networkTesting,
    )

    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Новый Assessment", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text("Параметры проекта и контекст анализа", color = MaterialTheme.colorScheme.onSurfaceVariant)

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.62f)),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(projectName, { projectName = it.take(160) }, label = { Text("Название проекта") }, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(organization, { organization = it.take(200) }, label = { Text("Организация / владелец") }, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(purpose, { purpose = it.take(400) }, label = { Text("Цель тестирования") }, modifier = Modifier.fillMaxWidth())
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.62f)),
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Режимы", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    ScopeCheck("Статический анализ", staticAnalysis) { staticAnalysis = it }
                    ScopeCheck("Reverse engineering", reverseEngineering) { reverseEngineering = it }
                    ScopeCheck("Динамический анализ в изолированной лаборатории", dynamicAnalysis) { dynamicAnalysis = it }
                    ScopeCheck("Тестирование сетевого/API-контура", networkTesting) { networkTesting = it }
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.38f)),
            ) {
                Column(Modifier.padding(14.dp)) {
                    ScopeCheck(
                        "Подтверждаю право проводить указанный анализ выбранного приложения/системы.",
                        authority,
                    ) { authority = it }
                }
            }

            Button(onClick = { onCreate(scope) }, enabled = scope.isValid, modifier = Modifier.fillMaxWidth()) {
                Text("Создать Assessment")
            }
        }
    }
}

@Composable
private fun ScopeCheck(text: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChecked)
        Text(text, modifier = Modifier.padding(start = 8.dp))
    }
}
