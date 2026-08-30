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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.R
import org.unirevlab.security.data.AgreementStore

@Composable
fun AgreementScreen(error: String? = null, onAccept: (String) -> Unit) {
    var signerName by remember { mutableStateOf("") }
    var lawful by remember { mutableStateOf(false) }
    var authorized by remember { mutableStateOf(false) }
    var understands by remember { mutableStateOf(false) }
    val canAccept = signerName.trim().length >= 2 && lawful && authorized && understands

    Surface(Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Image(painterResource(R.drawable.unirevlab_logo), "UniRevLab Security", Modifier.size(72.dp))
                Column(Modifier.weight(1f)) {
                    Text("UniRevLab Security", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                    Text("Авторизованный анализ приложений", color = MaterialTheme.colorScheme.primary)
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.62f)),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Соглашение об использовании", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                    Text("Версия ${AgreementStore.CURRENT_AGREEMENT_VERSION}", color = MaterialTheme.colorScheme.secondary)
                    Text(AgreementStore.AGREEMENT_TEXT)
                    Text("SHA-256: ${AgreementStore.AGREEMENT_TEXT_SHA256}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }

            if (error != null) Text("Ошибка подписи: $error", color = MaterialTheme.colorScheme.error)

            OutlinedTextField(
                value = signerName,
                onValueChange = { signerName = it.take(160) },
                label = { Text("Имя / ФИО подписанта") },
                supportingText = { Text("Сохраняется в локальной квитанции принятия условий") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.38f)),
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    AgreementCheck("Я буду использовать приложение только в законных целях.", lawful) { lawful = it }
                    AgreementCheck("У меня есть право или разрешение на анализ выбранных целей.", authorized) { authorized = it }
                    AgreementCheck("Я понимаю назначение и условия использования инструмента.", understands) { understands = it }
                }
            }

            Button(onClick = { onAccept(signerName.trim()) }, enabled = canAccept, modifier = Modifier.fillMaxWidth()) {
                Text("Подписать и продолжить")
            }
        }
    }
}

@Composable
private fun AgreementCheck(text: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChecked)
        Text(text, modifier = Modifier.padding(start = 8.dp))
    }
}
