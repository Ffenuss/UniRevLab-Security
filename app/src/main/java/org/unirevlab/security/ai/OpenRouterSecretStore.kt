package org.unirevlab.security.ai

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class OpenRouterSecretStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun hasKey(): Boolean = preferences.contains(KEY_CIPHERTEXT) && preferences.contains(KEY_IV)

    fun saveKey(raw: String) {
        val key = raw.trim()
        require(key.length in 20..512 && key.none(Char::isWhitespace)) { "Некорректный формат API-ключа" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(key.toByteArray(Charsets.UTF_8))
        preferences.edit()
            .putString(KEY_CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .apply()
    }

    fun loadKey(): String? {
        val encrypted = preferences.getString(KEY_CIPHERTEXT, null) ?: return null
        val iv = preferences.getString(KEY_IV, null) ?: return null
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                keyStore().getKey(KEY_ALIAS, null) as SecretKey,
                GCMParameterSpec(GCM_TAG_BITS, Base64.decode(iv, Base64.NO_WRAP)),
            )
            String(cipher.doFinal(Base64.decode(encrypted, Base64.NO_WRAP)), Charsets.UTF_8)
        }.getOrElse {
            clearKey()
            null
        }
    }

    fun clearKey() {
        preferences.edit().remove(KEY_CIPHERTEXT).remove(KEY_IV).apply()
        runCatching { keyStore().deleteEntry(KEY_ALIAS) }
    }

    fun selectedModelId(): String = preferences.getString(KEY_MODEL_ID, DEFAULT_MODEL_ID).orEmpty().ifBlank { DEFAULT_MODEL_ID }

    fun saveSelectedModelId(modelId: String) {
        require(MODEL_ID.matches(modelId)) { "Некорректный ID модели" }
        preferences.edit().putString(KEY_MODEL_ID, modelId).apply()
    }

    private fun getOrCreateKey(): SecretKey {
        val existing = keyStore().getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            generateKey()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    companion object {
        const val DEFAULT_MODEL_ID = "openrouter/free"
        private const val PREFERENCES = "openrouter_ai"
        private const val KEY_ALIAS = "unirevlab.openrouter.api-key.v1"
        private const val KEY_CIPHERTEXT = "api_key_ciphertext"
        private const val KEY_IV = "api_key_iv"
        private const val KEY_MODEL_ID = "selected_model_id"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private val MODEL_ID = Regex("[A-Za-z0-9._~:-]+/[A-Za-z0-9._~:-]+")
    }
}
