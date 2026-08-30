package org.unirevlab.security.analysis

import org.unirevlab.security.model.ComponentExposure
import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.DeepLinkDeclaration
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.ProviderDeclaration
import org.unirevlab.security.model.SecurityReference
import org.unirevlab.security.model.Severity

object ManifestRuleEngine {
    fun evaluate(manifest: ManifestSummary): List<Finding> = buildList {
        if (manifest.debuggable) add(debuggableFinding())
        if (manifest.usesCleartextTraffic && manifest.networkSecurityConfigConfigured != true) {
            add(cleartextFinding(manifest.networkSecurityConfigConfigured))
        }
        if (manifest.dangerousPermissions.isNotEmpty()) add(dangerousPermissionsFinding(manifest.dangerousPermissions))
        if (manifest.allowBackup &&
            manifest.fullBackupContentConfigured != true &&
            manifest.dataExtractionRulesConfigured != true
        ) {
            add(backupFinding(
                rulesKnownAbsent = manifest.fullBackupContentConfigured == false &&
                    manifest.dataExtractionRulesConfigured == false
            ))
        }

        val exposedProviders = manifest.components.filter {
            it.kind == "provider" && it.exported && it.permissions.isEmpty()
        }
        if (exposedProviders.isNotEmpty()) add(exportedProviderFinding(exposedProviders))

        val uriGrantProviders = manifest.providers.filter { provider ->
            provider.exported == true && provider.grantUriPermissions && provider.readPermission == null && provider.writePermission == null
        }
        if (uriGrantProviders.isNotEmpty()) add(exportedUriGrantProviderFinding(uriGrantProviders))

        val unprotected = manifest.components.filter {
            it.kind != "provider" && it.exported && it.permissions.isEmpty()
        }
        if (unprotected.isNotEmpty()) add(exportedComponentsReview(unprotected))

        val protectionByName = manifest.declaredPermissions.associate { it.name to it.protectionLevel }
        val weaklyProtected = manifest.components.filter { component ->
            component.exported && component.permissions.any {
                protectionByName[it] in setOf("NORMAL", "DANGEROUS")
            }
        }
        if (weaklyProtected.isNotEmpty()) add(weakComponentPermissionFinding(weaklyProtected, protectionByName))

        val unverifiedWebLinks = manifest.deepLinks.filter { link ->
            link.schemes.any { it.equals("http", true) || it.equals("https", true) } && !link.autoVerify
        }
        if (unverifiedWebLinks.isNotEmpty()) add(unverifiedAppLinksFinding(unverifiedWebLinks))

        val customSchemes = manifest.deepLinks.filter { link ->
            link.schemes.any { !it.equals("http", true) && !it.equals("https", true) }
        }
        if (customSchemes.isNotEmpty()) add(customSchemeReviewFinding(customSchemes))

        val patternedLinks = manifest.deepLinks.filter { it.pathPatterns.isNotEmpty() }
        if (patternedLinks.isNotEmpty()) add(pathPatternReviewFinding(patternedLinks))

        if (manifest.signingSchemes == listOf("V1_JAR")) add(v1OnlySignatureFinding(manifest.minSdk))
        if (manifest.signingSchemes.isEmpty() && manifest.signingCertificateSha256.isNotEmpty()) {
            add(unclassifiedSignatureSchemeFinding(manifest.signingParseError))
        }

        manifest.networkSecurity?.let { network ->
            val cleartextDomains = network.domainConfigs.filter { it.cleartextTrafficPermitted == true }
            if (network.baseCleartextTrafficPermitted == true || cleartextDomains.isNotEmpty()) {
                add(networkConfigCleartextFinding(network.baseCleartextTrafficPermitted == true, cleartextDomains))
            }
            val userAnchors = network.trustAnchors.filter { !it.inDebugOverrides && it.source.equals("user", true) }
            if (userAnchors.isNotEmpty()) add(userTrustAnchorFinding(userAnchors.size))
        }
    }.sortedWith(compareBy<Finding>({ severityOrder(it.severity) }, { it.id }))

    private fun debuggableFinding() = Finding(
        id = "ANDROID-MANIFEST-DEBUGGABLE",
        title = "Release application is debuggable",
        severity = Severity.HIGH,
        confidence = Confidence.CONFIRMED,
        category = "RESILIENCE",
        description = "The manifest-derived ApplicationInfo contains the debuggable flag. A production release should not expose debugger access unless explicitly required by the assessment target.",
        evidence = listOf(Evidence("AndroidManifest.xml", "<application>", "android:debuggable=true")),
        remediation = "Build the production variant with android:debuggable=false and verify that release build configuration cannot re-enable it.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0226"),
            SecurityReference("OWASP MASVS", "MASVS-RESILIENCE"),
        ),
    )

    private fun cleartextFinding(networkConfigKnown: Boolean?) = Finding(
        id = "ANDROID-MANIFEST-CLEARTEXT",
        title = "Application may allow cleartext network traffic",
        severity = Severity.HIGH,
        confidence = if (networkConfigKnown == false) Confidence.HIGH else Confidence.LOW,
        category = "NETWORK",
        description = if (networkConfigKnown == false) {
            "The application enables cleartext traffic and no Network Security Configuration was detected."
        } else {
            "The application-derived flags indicate cleartext traffic is enabled. Android ignores this flag when a Network Security Configuration is present, so the referenced configuration must be checked before treating this as confirmed."
        },
        evidence = listOf(Evidence("AndroidManifest.xml", "<application>", "android:usesCleartextTraffic=true")),
        remediation = "Disable cleartext traffic for production. If narrowly scoped exceptions are required, use a Network Security Configuration with explicit domains and review every cleartextTrafficPermitted rule.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0235"),
            SecurityReference("OWASP MASVS", "MASVS-NETWORK"),
        ),
        requiresManualReview = networkConfigKnown == null,
    )

    private fun dangerousPermissionsFinding(permissions: List<String>) = Finding(
        id = "ANDROID-DANGEROUS-PERMISSIONS",
        title = "Dangerous Android permissions require product justification",
        severity = Severity.LOW,
        confidence = Confidence.HIGH,
        category = "PRIVACY",
        description = "The target requests one or more permissions classified as dangerous by the Android version performing the assessment. Their presence is not automatically a defect, but every permission should be necessary for a documented user-facing feature and minimized where privacy-preserving alternatives exist.",
        evidence = permissions.map { Evidence("AndroidManifest.xml", "<uses-permission>", it) },
        remediation = "Remove permissions that are not strictly required, request runtime access only when needed, provide user rationale, and prefer platform-mediated alternatives that avoid direct access to sensitive data where practical.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0254"),
            SecurityReference("OWASP MASVS", "MASVS-PRIVACY"),
        ),
        requiresManualReview = true,
    )

    private fun backupFinding(rulesKnownAbsent: Boolean) = Finding(
        id = "ANDROID-MANIFEST-BACKUP",
        title = "Backup configuration requires sensitive-data review",
        severity = if (rulesKnownAbsent) Severity.MEDIUM else Severity.LOW,
        confidence = if (rulesKnownAbsent) Confidence.MEDIUM else Confidence.LOW,
        category = "STORAGE",
        description = if (rulesKnownAbsent) {
            "Application backup is enabled and no explicit backup/data-extraction rules were detected."
        } else {
            "Application backup is enabled. The referenced backup/data-extraction resources must be inspected before deciding whether sensitive data can be backed up."
        },
        evidence = listOf(Evidence("AndroidManifest.xml", "<application>", "android:allowBackup=true")),
        remediation = "Define backup/data-extraction rules that exclude sensitive material, or disable backup if the product does not require it. Validate effective backup behavior on supported Android versions.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0262"),
            SecurityReference("OWASP MASVS", "MASVS-STORAGE"),
        ),
        requiresManualReview = true,
    )

    private fun exportedProviderFinding(components: List<ComponentExposure>) = Finding(
        id = "ANDROID-EXPORTED-PROVIDER-UNPROTECTED",
        title = "Exported content provider has no manifest-level access permission",
        severity = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        category = "PLATFORM",
        description = "At least one exported content provider does not declare a read, write, or combined manifest-level permission. Whether sensitive data is actually exposed depends on the provider implementation and therefore still requires code review.",
        evidence = components.take(50).map {
            Evidence("AndroidManifest.xml", "provider:${it.name}", "exported=true; permission=<none>")
        },
        remediation = "Make the provider non-exported when external access is unnecessary. Otherwise require appropriately protected read/write permissions and validate authorization in provider operations.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0355"),
            SecurityReference("OWASP MASVS", "MASVS-PLATFORM"),
        ),
        requiresManualReview = true,
    )

    private fun exportedUriGrantProviderFinding(providers: List<ProviderDeclaration>) = Finding(
        id = "ANDROID-EXPORTED-PROVIDER-URI-GRANTS",
        title = "Exported provider permits URI grants without a manifest permission",
        severity = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        category = "PLATFORM",
        description = "An exported content provider enables grantUriPermissions while declaring no provider-level read or write permission. URI grants can be valid by design, but the exposed paths and every grant call require authorization review.",
        evidence = providers.take(50).map { provider ->
            Evidence(
                "AndroidManifest.xml",
                "provider:${provider.name}",
                "authorities=${provider.authorities.joinToString().ifEmpty { "<unspecified>" }}; grantUriPermissions=true; readPermission=<none>; writePermission=<none>",
            )
        },
        remediation = "Prefer non-exported providers for internal data. For intentional sharing, constrain authorities and grantable paths, use appropriate read/write permissions, and issue temporary URI grants only after caller authorization.",
        references = listOf(
            SecurityReference("OWASP MASVS", "MASVS-PLATFORM"),
            SecurityReference("Android", "Content providers / URI permissions"),
        ),
        requiresManualReview = true,
    )

    private fun exportedComponentsReview(components: List<ComponentExposure>) = Finding(
        id = "ANDROID-EXPORTED-UNPROTECTED-REVIEW",
        title = "Exported components without manifest-level permission require review",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.LOW,
        category = "PLATFORM",
        description = "One or more exported activities, services, or broadcast receivers have no manifest-level permission. Exported components are not automatically vulnerable; their reachable code and inputs must be reviewed for sensitive functionality and authorization checks.",
        evidence = components.take(50).map {
            Evidence("AndroidManifest.xml", "${it.kind}:${it.name}", "exported=true; permission=<none>")
        },
        remediation = "Review every listed component. Add an appropriate permission or make the component non-exported when external callers are unnecessary; otherwise enforce authorization and strict input validation in reachable code.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0364/0365/0366"),
            SecurityReference("OWASP MASVS", "MASVS-PLATFORM"),
        ),
        requiresManualReview = true,
    )

    private fun weakComponentPermissionFinding(
        components: List<ComponentExposure>,
        protectionByName: Map<String, String>,
    ) = Finding(
        id = "ANDROID-EXPORTED-WEAK-PERMISSION",
        title = "Exported component relies on broadly grantable custom permission",
        severity = Severity.LOW,
        confidence = Confidence.HIGH,
        category = "PLATFORM",
        description = "An exported component is protected by an app-declared permission whose base protection level is normal or dangerous. Such permissions may be granted to untrusted apps and should not be treated as a strong trust boundary for sensitive functionality.",
        evidence = components.take(50).flatMap { component ->
            component.permissions.mapNotNull { permission ->
                protectionByName[permission]?.takeIf { it == "NORMAL" || it == "DANGEROUS" }?.let { level ->
                    Evidence("AndroidManifest.xml", "${component.kind}:${component.name}", "$permission protectionLevel=$level")
                }
            }
        },
        remediation = "If access should be limited to trusted same-signer apps, use an appropriately scoped signature-level permission. Independently enforce authorization in the component before performing sensitive operations.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-BEST-0052"),
            SecurityReference("OWASP MASVS", "MASVS-PLATFORM"),
        ),
        requiresManualReview = true,
    )

    private fun unverifiedAppLinksFinding(links: List<DeepLinkDeclaration>) = Finding(
        id = "ANDROID-UNVERIFIED-APP-LINKS",
        title = "HTTP(S) deep links do not request App Link verification",
        severity = Severity.MEDIUM,
        confidence = Confidence.CONFIRMED,
        category = "PLATFORM",
        description = "Browsable VIEW intent filters declare HTTP or HTTPS deep links without android:autoVerify=true. Android cannot establish domain ownership for those filters, allowing competing apps to claim the same links.",
        evidence = links.take(50).map { link ->
            Evidence(
                "AndroidManifest.xml",
                "activity:${link.componentName}",
                "schemes=${link.schemes.joinToString()}; hosts=${link.hosts.joinToString().ifEmpty { "<unspecified>" }}; autoVerify=false",
            )
        },
        remediation = "Use verified Android App Links for web URLs: set android:autoVerify=true and publish a valid Digital Asset Links association for every declared host. Confirm verification dynamically on supported Android versions.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0393"),
            SecurityReference("OWASP MASVS", "MASVS-PLATFORM"),
        ),
    )

    private fun customSchemeReviewFinding(links: List<DeepLinkDeclaration>) = Finding(
        id = "ANDROID-CUSTOM-SCHEME-REVIEW",
        title = "Custom URL scheme handlers require untrusted-input review",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.HIGH,
        category = "PLATFORM",
        description = "The app declares browsable VIEW handlers for one or more non-HTTP(S) URL schemes. Custom schemes cannot be verified as domain-owned on Android; the handler must treat every URI and parameter as attacker-controlled input.",
        evidence = links.take(50).map { link ->
            val custom = link.schemes.filterNot { it.equals("http", true) || it.equals("https", true) }
            Evidence("AndroidManifest.xml", "activity:${link.componentName}", "customSchemes=${custom.joinToString()}")
        },
        remediation = "Prefer verified App Links for sensitive flows. For custom schemes, validate scheme/host/path/query values against strict allowlists before navigation, file access, WebView use, authentication transitions, or business actions.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0394"),
            SecurityReference("OWASP MASVS", "MASVS-PLATFORM"),
        ),
        requiresManualReview = true,
    )

    private fun pathPatternReviewFinding(links: List<DeepLinkDeclaration>) = Finding(
        id = "ANDROID-DEEP-LINK-PATH-PATTERN-REVIEW",
        title = "Deep-link pathPattern handlers require route validation review",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.HIGH,
        category = "PLATFORM",
        description = "Browsable VIEW intent filters use android:pathPattern. Pattern matching can intentionally cover broad URI sets, so reachable routes and parameters should be treated as untrusted input and compared with the app's authorization model.",
        evidence = links.take(50).map { link ->
            Evidence("AndroidManifest.xml", "activity:${link.componentName}", "hosts=${link.hosts.joinToString()}; pathPatterns=${link.pathPatterns.joinToString()}")
        },
        remediation = "Keep path patterns as narrow as product requirements allow and enforce allowlisted route/parameter validation inside the receiving component before sensitive navigation or actions.",
        references = listOf(
            SecurityReference("OWASP MASVS", "MASVS-PLATFORM"),
            SecurityReference("Android", "Intent filters / data matching"),
        ),
        requiresManualReview = true,
    )

    private fun networkConfigCleartextFinding(
        baseEnabled: Boolean,
        domains: List<org.unirevlab.security.model.NetworkDomainConfigSummary>,
    ) = Finding(
        id = "ANDROID-NETWORK-CONFIG-CLEARTEXT",
        title = "Network Security Config explicitly permits cleartext traffic",
        severity = Severity.HIGH,
        confidence = Confidence.CONFIRMED,
        category = "NETWORK",
        description = "The packaged Network Security Config contains an explicit cleartextTrafficPermitted=true policy at the base or domain-config level.",
        evidence = buildList {
            if (baseEnabled) add(Evidence("Network Security Config", "base-config", "cleartextTrafficPermitted=true"))
            domains.take(20).forEach { domain ->
                add(Evidence("Network Security Config", "domain-config", "cleartextTrafficPermitted=true; domains=${domain.domains.joinToString().ifBlank { "<unresolved>" }}"))
            }
        },
        remediation = "Require TLS by default. Keep cleartext disabled globally and remove domain exceptions unless a documented legacy endpoint cannot be migrated; validate that no sensitive data traverses any exception.",
        references = listOf(
            SecurityReference("OWASP MASVS", "MASVS-NETWORK"),
            SecurityReference("Android", "Network Security Configuration"),
        ),
    )

    private fun userTrustAnchorFinding(count: Int) = Finding(
        id = "ANDROID-NETWORK-USER-CA-TRUST",
        title = "Production Network Security Config trusts user-installed CAs",
        severity = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        category = "NETWORK",
        description = "One or more non-debug trust-anchor declarations use src=\"user\". This expands the production trust store to certificates installed by the device user or administrator and can weaken transport trust assumptions.",
        evidence = listOf(Evidence("Network Security Config", "trust-anchors/certificates", "src=user; declarations=$count")),
        remediation = "Do not trust user-installed CAs in production unless the product has an explicit enterprise interception requirement. If needed only for development, place the trust anchor under debug-overrides.",
        references = listOf(
            SecurityReference("OWASP MASVS", "MASVS-NETWORK"),
            SecurityReference("Android", "Network Security Configuration"),
        ),
        requiresManualReview = true,
    )

    private fun v1OnlySignatureFinding(minSdk: Int?) = Finding(
        id = "ANDROID-SIGNATURE-V1-ONLY",
        title = "APK appears to use only JAR/v1 signing",
        severity = if (minSdk == null || minSdk <= 25) Severity.MEDIUM else Severity.LOW,
        confidence = Confidence.HIGH,
        category = "CODE",
        description = "The APK contains a JAR/v1 signature but no v2/v3/v3.1 signing block was detected. For older Android compatibility this can materially weaken package-integrity guarantees; for modern releases it is also a release-hardening signal.",
        evidence = listOf(Evidence("APK signing", "signingSchemes", "V1_JAR only; minSdk=${minSdk ?: "unknown"}")),
        remediation = "Sign production APKs with the modern Android APK Signature Scheme supported by the release toolchain (normally v2 and/or newer as appropriate) and preserve expected certificate identity across updates.",
        references = listOf(SecurityReference("Android", "APK Signature Scheme")),
        requiresManualReview = true,
    )

    private fun unclassifiedSignatureSchemeFinding(parseError: String?) = Finding(
        id = "ANDROID-SIGNATURE-SCHEME-UNCLASSIFIED",
        title = "APK signature scheme could not be classified",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.LOW,
        category = "CODE",
        description = "Android PackageManager exposed signing certificate material, but the local passive signing-block scanner did not classify a v1/v2/v3/v3.1 scheme. This may indicate an unsupported container/signing layout or a parser limitation.",
        evidence = listOf(Evidence("APK signing", "signingSchemes", parseError ?: "certificate present; scheme not classified")),
        remediation = "Verify the APK with the platform build/signing tooling and compare the certificate and signing schemes with the expected release policy.",
        references = listOf(SecurityReference("Android", "APK Signature Scheme")),
        requiresManualReview = true,
    )

    private fun severityOrder(severity: Severity): Int = when (severity) {
        Severity.CRITICAL -> 0
        Severity.HIGH -> 1
        Severity.MEDIUM -> 2
        Severity.LOW -> 3
        Severity.INFORMATIONAL -> 4
    }
}
