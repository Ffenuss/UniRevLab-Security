package org.unirevlab.security.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val UniRevLabDarkColors = darkColorScheme(
    primary = Color(0xFF9B6CFF),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF38206B),
    onPrimaryContainer = Color(0xFFEBDDFF),
    secondary = Color(0xFF58D8FF),
    onSecondary = Color(0xFF001F29),
    secondaryContainer = Color(0xFF103D4B),
    onSecondaryContainer = Color(0xFFB8EAFA),
    tertiary = Color(0xFF62E39A),
    onTertiary = Color(0xFF00391E),
    background = Color(0xFF090D17),
    onBackground = Color(0xFFE8ECF8),
    surface = Color(0xFF0E1421),
    onSurface = Color(0xFFE8ECF8),
    surfaceVariant = Color(0xFF171E2D),
    onSurfaceVariant = Color(0xFFBAC4D8),
    outline = Color(0xFF364158),
    error = Color(0xFFFF6F7F),
    onError = Color(0xFF40000A),
)

@Composable
fun UniRevLabTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = UniRevLabDarkColors,
        content = content,
    )
}
