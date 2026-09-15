package dev.modkit.mobile;

/**
 * Binary-compatibility alias for pre-1.1 shortcuts/notifications.
 *
 * It inherits the real v1.1 FullModeActivity directly, so old intents no longer create
 * a second activity or perform a legacy redirect hop.
 */
public class MainActivity extends FullModeActivity {}
