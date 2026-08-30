package org.unirevlab.security.model

import java.util.UUID

data class AssessmentScope(
    val assessmentId: String = UUID.randomUUID().toString(),
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val projectName: String,
    val organization: String,
    val purpose: String,
    val confirmsAuthority: Boolean,
    val staticAnalysis: Boolean = true,
    val reverseEngineering: Boolean = true,
    val dynamicAnalysis: Boolean = false,
    val networkTesting: Boolean = false,
) : java.io.Serializable {
    val isValid: Boolean
        get() = projectName.isNotBlank() &&
            organization.isNotBlank() &&
            purpose.isNotBlank() &&
            confirmsAuthority
}
