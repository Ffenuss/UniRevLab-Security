package org.unirevlab.security.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val UniRevLabColors = darkColorScheme(
    primary = Color(0xFF71E7B4),
    onPrimary = Color(0xFF032017),
    primaryContainer = Color(0xFF123C31),
    onPrimaryContainer = Color(0xFF9AF3CB),
    secondary = Color(0xFFA7C8FF),
    onSecondary = Color(0xFF071A34),
    secondaryContainer = Color(0xFF172B48),
    onSecondaryContainer = Color(0xFFC8DBFF),
    tertiary = Color(0xFFFFC56F),
    onTertiary = Color(0xFF2B1900),
    background = Color(0xFF080D12),
    onBackground = Color(0xFFE5EDF5),
    surface = Color(0xFF0D141B),
    onSurface = Color(0xFFE5EDF5),
    surfaceVariant = Color(0xFF17212B),
    onSurfaceVariant = Color(0xFFB4C0CD),
    outline = Color(0xFF52606D),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
)

@Composable
fun UniRevLabTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = UniRevLabColors, content = content)
}
