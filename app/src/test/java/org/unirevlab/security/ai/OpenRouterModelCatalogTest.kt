package org.unirevlab.security.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenRouterModelCatalogTest {
    @Test
    fun keepsOnlyFreeTextModelsAndAddsRouter() {
        val raw = """
            {
              "data": [
                {
                  "id": "vendor/free-text:free",
                  "name": "Free Text",
                  "description": "usable",
                  "context_length": 262144,
                  "pricing": {"prompt": "0", "completion": "0.000000"},
                  "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]},
                  "supported_parameters": ["tools", "temperature"]
                },
                {
                  "id": "vendor/paid",
                  "name": "Paid",
                  "pricing": {"prompt": "0.0001", "completion": "0"},
                  "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]}
                },
                {
                  "id": "vendor/free-image",
                  "name": "Image only",
                  "pricing": {"prompt": "0", "completion": "0"},
                  "architecture": {"input_modalities": ["image"], "output_modalities": ["image"]}
                }
              ]
            }
        """.trimIndent()

        val models = OpenRouterModelCatalog.parseFreeModels(raw)

        assertEquals(listOf("openrouter/free", "vendor/free-text:free"), models.map { it.id })
        assertTrue(models.last().supportsTools)
        assertFalse(models.any { it.id == "vendor/paid" })
    }

    @Test
    fun parsesStringAndMultipartChatContent() {
        val plain = OpenRouterModelCatalog.parseChatResult(
            """{"model":"vendor/a","choices":[{"message":{"content":"Ответ"}}]}""",
            "openrouter/free",
        )
        val multipart = OpenRouterModelCatalog.parseChatResult(
            """{"choices":[{"message":{"content":[{"type":"text","text":"Часть 1. "},{"type":"text","text":"Часть 2."}]}}]}""",
            "vendor/b",
        )

        assertEquals("vendor/a", plain.modelId)
        assertEquals("Ответ", plain.text)
        assertEquals("Часть 1. Часть 2.", multipart.text)
    }
}
