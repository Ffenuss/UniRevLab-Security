package org.unirevlab.security.ui

import android.content.Context

enum class AppLanguage(val code: String) {
    RUSSIAN("ru"),
    ENGLISH("en");

    fun text(russian: String, english: String): String = if (this == RUSSIAN) russian else english

    companion object {
        fun fromCode(value: String?): AppLanguage = entries.firstOrNull { it.code == value } ?: RUSSIAN
    }
}

class AppLanguageStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun load(): AppLanguage = AppLanguage.fromCode(preferences.getString(KEY_LANGUAGE, null))

    fun save(language: AppLanguage) {
        preferences.edit().putString(KEY_LANGUAGE, language.code).apply()
    }

    companion object {
        private const val PREFERENCES = "ui_preferences"
        private const val KEY_LANGUAGE = "language"
    }
}
