from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "app/src/main/java/org/unirevlab/security/analysis/TamperAssessmentEngine.kt"
TEST = ROOT / "app/src/test/java/org/unirevlab/security/analysis/TamperAssessmentClassifierTest.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


def replace_regex_once(text: str, pattern: str, repl: str, label: str) -> str:
    updated, count = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return updated


text = ENGINE.read_text(encoding="utf-8")

# Patchers commonly pivot through client-side billing/license decisions. Extend the
# classifier with SDK/API names while keeping detection observation-only here.
text = replace_regex_once(
    text,
    r'("ENTITLEMENT_TRUST" to listOf\()([^\n]+)(\),)',
    lambda m: m.group(1) + m.group(2).rstrip()[:-1] + ', "billingclient", "billingresult", "purchased", "purchasehistory", "querypurchases", "querypurchasesasync", "queryproductdetails", "licensechecker", "checkaccess", "licensecontentprovider", "pairip")' + m.group(3),
    "entitlement terms",
)
text = replace_regex_once(
    text,
    r'("INTEGRITY" to listOf\()([^\n]+)(\),)',
    lambda m: m.group(1) + m.group(2).rstrip()[:-1] + ', "signinginfo", "apkcontentssigners", "signingcertificatehistory", "checksignature", "checksignatures", "certdigest", "appintegrity", "packageintegrity", "meetsdeviceintegrity", "meetsbasicintegrity")' + m.group(3),
    "integrity terms",
)

old_auth = '        "AUTH_SESSION" to listOf("apikey", "api_key", "clientsecret", "client_secret", "bearer", "sessiontoken", "auth_token", "accesstoken", "access_token"),\n'
new_auth = old_auth + '        "COMPONENT_TRUST" to listOf("licensecontentprovider", "integrityprovider", "attestationprovider", "licensingservice", "billingservice"),\n'
text = replace_once(text, old_auth, new_auth, "component trust category")

old_scores = '    private val CATEGORY_SCORES = mapOf("ENTITLEMENT_TRUST" to 70, "LOCAL_STATE" to 60, "FEATURE_CONFIG" to 48, "INTEGRITY" to 56, "AUTH_SESSION" to 68)'
new_scores = '    private val CATEGORY_SCORES = mapOf("ENTITLEMENT_TRUST" to 70, "LOCAL_STATE" to 60, "FEATURE_CONFIG" to 48, "INTEGRITY" to 56, "AUTH_SESSION" to 68, "COMPONENT_TRUST" to 58)'
text = replace_once(text, old_scores, new_scores, "category scores")

old_compound = '    private val COMPOUND_TERMS = setOf("isowned", "ispro", "hasaccess", "accesslevel", "featureflag", "remoteconfig", "playintegrity", "rootcheck", "emulatorcheck", "apikey", "clientsecret", "sessiontoken", "authtoken", "accesstoken")'
new_compound = '    private val COMPOUND_TERMS = setOf("isowned", "ispro", "hasaccess", "accesslevel", "featureflag", "remoteconfig", "playintegrity", "rootcheck", "emulatorcheck", "apikey", "clientsecret", "sessiontoken", "authtoken", "accesstoken", "billingclient", "billingresult", "purchasehistory", "querypurchases", "querypurchasesasync", "queryproductdetails", "licensechecker", "checkaccess", "licensecontentprovider", "signinginfo", "apkcontentssigners", "signingcertificatehistory", "checksignature", "checksignatures", "certdigest", "appintegrity", "packageintegrity", "meetsdeviceintegrity", "meetsbasicintegrity", "integrityprovider", "attestationprovider", "licensingservice", "billingservice")'
text = replace_once(text, old_compound, new_compound, "compound terms")

old_title = '        "AUTH_SESSION" -> "auth/session material"\n'
new_title = old_title + '        "COMPONENT_TRUST" -> "security-sensitive Android component dependency"\n'
text = replace_once(text, old_title, new_title, "component title")

# The earlier scanner looked at methods, strings, fields and constants, but not
# calls into external SDKs. This is the critical bridge for BillingClient,
# licensing libraries, PackageManager signing APIs and Play Integrity.
anchor = '        var genericConstants = 0\n'
call_scan = '''        dex?.callXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach
            if (!isEditableProjectMethod(method)) return@forEach
            val callee = "${xref.calleeClass} ${xref.calleeName} ${xref.calleePrototype}"
            categoriesFor(callee).forEach { (category, score) ->
                hit(
                    SurfaceHit(
                        category = category,
                        kind = "DEX_CALL",
                        location = "${xref.dexEntry}:${method.declaringClass}->${method.name}${method.prototype}",
                        preview = safePreview("calls ${xref.calleeClass}->${xref.calleeName}${xref.calleePrototype}"),
                        score = score,
                        dexEntry = method.dexEntry,
                        classDescriptor = method.declaringClass,
                        methodName = method.name,
                        prototype = method.prototype,
                    ),
                )
            }
        }

'''
text = replace_once(text, anchor, call_scan + anchor, "DEX call xref scan")

old_weight = '        "DEX_FIELD" -> 0.95\n'
new_weight = old_weight + '        "DEX_CALL" -> 0.98\n'
text = replace_once(text, old_weight, new_weight, "DEX call evidence weight")

# Explain why removable/disableable local components are a trust-boundary risk
# without generating a component-disabling patch.
advice_anchor = '        val highRiskSecrets = assessment.secrets.filterNot { it.kind == "GOOGLE_API_KEY_LIKE" || it.kind == "PRIVATE_KEY_MARKER" }\n'
advice = '''        if (categories.containsKey("COMPONENT_TRUST")) {
            out += HardeningSuggestion(
                "HIGH", "Не доверять наличию локального security-компонента как границе доступа",
                "Обнаружены provider/service точки, связанные с лицензированием, billing или integrity; локальный APK и его manifest находятся под контролем атакующего.",
                listOf(
                    "Считать provider/service/receiver в клиенте изменяемыми и не делать их единственным источником решения о доступе.",
                    "На backend независимо проверять entitlement/receipt/attestation и привязывать результат к session/nonce.",
                    "После изменений защиты повторно проверять сценарии удаления, отключения или переподписания компонентов как негативные тесты.",
                ),
            )
        }
'''
text = replace_once(text, advice_anchor, advice + advice_anchor, "component hardening advice")

ENGINE.write_text(text, encoding="utf-8")

# Regression tests use only classifier names; they document coverage but do not
# contain a recipe for bypassing any target application.
test = TEST.read_text(encoding="utf-8")
test_anchor = '    @Test\n    fun repeatedWeakArchiveSignalsDoNotExplodeOverallScore() {\n'
new_tests = '''    @Test
    fun billingAndLicensingSdkSurfacesClassifyAsEntitlementTrust() {
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("BillingClient queryPurchasesAsync"))
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("LicenseChecker checkAccess"))
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("com.pairip.licensecheck.LicenseContentProvider"))
    }

    @Test
    fun signingAndIntegrityApisClassifyAsIntegrityTrust() {
        assertTrue("INTEGRITY" in TamperAssessmentEngine.categoriesForTesting("SigningInfo getApkContentsSigners"))
        assertTrue("INTEGRITY" in TamperAssessmentEngine.categoriesForTesting("PackageManager checkSignatures"))
        assertTrue("INTEGRITY" in TamperAssessmentEngine.categoriesForTesting("appIntegrity meetsDeviceIntegrity"))
    }

    @Test
    fun securitySensitiveComponentsReceiveDedicatedCoverage() {
        assertTrue("COMPONENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("LicenseContentProvider"))
        assertTrue("COMPONENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("IntegrityProvider"))
        assertFalse("COMPONENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("ordinary ContentProvider"))
    }

'''
test = replace_once(test, test_anchor, new_tests + test_anchor, "classifier regression tests")
TEST.write_text(test, encoding="utf-8")

print("Applied v0.26.0 defensive patch-technique coverage")
