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

    @Test
    fun requestDataPolicyIsExplicitAndFailureIsClassified() {
        val client = OpenRouterClient()
        val model = OpenRouterModel("vendor/model:free", "Model", "", 64_000, false)
        val context = ReportContext("evidence", 8, 1, 1, true)

        val strict = client.buildPayload(model, context, emptyList(), "question", OpenRouterDataPolicy.STRICT)
        val compatible = client.buildPayload(model, context, emptyList(), "question", OpenRouterDataPolicy.FREE_MODEL_COMPATIBLE)

        assertEquals("deny", strict.getJSONObject("provider").getString("data_collection"))
        assertEquals("allow", compatible.getJSONObject("provider").getString("data_collection"))
        val english = client.buildPayload(model, context, emptyList(), "question", OpenRouterDataPolicy.STRICT, "en")
        assertTrue(english.getJSONArray("messages").getJSONObject(0).getString("content").contains("Answer in English"))
        assertEquals(
            OpenRouterFailureReason.DATA_POLICY_NO_ENDPOINT,
            classifyOpenRouterFailure(404, "No endpoints found matching your data policy (Free model training)"),
        )
        assertEquals(OpenRouterFailureReason.GENERAL, classifyOpenRouterFailure(404, "Model not found"))
    }
}
