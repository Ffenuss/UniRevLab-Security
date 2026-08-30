package org.unirevlab.security.analysis

import org.unirevlab.security.model.DeepLinkDeclaration
import org.unirevlab.security.model.ProviderDeclaration

/** Security-relevant attributes and intent-filter data not exposed reliably by archive PackageManager APIs. */
data class AxmlManifestOverlay(
    val fullBackupContentConfigured: Boolean?,
    val dataExtractionRulesConfigured: Boolean?,
    val networkSecurityConfigConfigured: Boolean?,
    val fullBackupContentReference: String? = null,
    val dataExtractionRulesReference: String? = null,
    val networkSecurityConfigReference: String? = null,
    val deepLinks: List<DeepLinkDeclaration>,
    val providers: List<ProviderDeclaration> = emptyList(),
)
