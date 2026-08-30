package org.unirevlab.security.analysis

import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.DeepLinkDeclaration
import org.unirevlab.security.model.ProviderDeclaration
import org.unirevlab.security.model.ProviderPathPermissionSummary

object AxmlManifestOverlayParser {
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    private const val ACTION_VIEW = "android.intent.action.VIEW"
    private const val CATEGORY_BROWSABLE = "android.intent.category.BROWSABLE"

    fun parse(nativeJson: String?): AxmlManifestOverlay? {
        if (nativeJson.isNullOrBlank()) return null
        return runCatching {
            val root = JSONObject(nativeJson)
            if (root.has("error")) return null
            val elements = root.getJSONArray("elements")
            val application = firstElement(elements, "application")
            val fullBackup = application?.let { androidAttr(it, "fullBackupContent") }
            val extraction = application?.let { androidAttr(it, "dataExtractionRules") }
            val network = application?.let { androidAttr(it, "networkSecurityConfig") }

            AxmlManifestOverlay(
                fullBackupContentConfigured = fullBackup?.let { it.isNotBlank() && it != "false" } ?: false,
                dataExtractionRulesConfigured = extraction?.let { it.isNotBlank() } ?: false,
                networkSecurityConfigConfigured = network?.let { it.isNotBlank() } ?: false,
                fullBackupContentReference = fullBackup,
                dataExtractionRulesReference = extraction,
                networkSecurityConfigReference = network,
                deepLinks = parseDeepLinks(elements),
                providers = parseProviders(elements),
            )
        }.getOrNull()
    }

    private fun firstElement(elements: JSONArray, name: String): JSONObject? {
        for (i in 0 until elements.length()) {
            val element = elements.getJSONObject(i)
            if (element.optString("name") == name) return element
        }
        return null
    }

    private fun parseDeepLinks(elements: JSONArray): List<DeepLinkDeclaration> {
        var componentName: String? = null
        var componentDepth = -1
        var filter: IntentFilterState? = null
        val results = mutableListOf<DeepLinkDeclaration>()

        fun finishFilter() {
            val state = filter ?: return
            if (state.schemes.isNotEmpty() && state.viewAction && state.browsable) {
                results += DeepLinkDeclaration(
                    componentName = state.componentName,
                    schemes = state.schemes.toSortedSet().toList(),
                    hosts = state.hosts.toSortedSet().toList(),
                    autoVerify = state.autoVerify,
                    browsable = true,
                    viewAction = true,
                    ports = state.ports.toSortedSet().toList(),
                    paths = state.paths.toSortedSet().toList(),
                    pathPrefixes = state.pathPrefixes.toSortedSet().toList(),
                    pathPatterns = state.pathPatterns.toSortedSet().toList(),
                    mimeTypes = state.mimeTypes.toSortedSet().toList(),
                )
            }
            filter = null
        }

        for (i in 0 until elements.length()) {
            val element = elements.getJSONObject(i)
            val depth = element.optInt("depth", -1)
            val name = element.optString("name")

            if (filter != null && depth <= filter!!.depth) finishFilter()
            if (componentName != null && depth <= componentDepth && name !in COMPONENT_NAMES) {
                componentName = null
                componentDepth = -1
            }

            if (name in COMPONENT_NAMES) {
                finishFilter()
                componentName = androidAttr(element, "name") ?: "<unnamed-component>"
                componentDepth = depth
                continue
            }

            if (name == "intent-filter" && componentName != null && depth > componentDepth) {
                finishFilter()
                filter = IntentFilterState(
                    componentName = componentName!!,
                    depth = depth,
                    autoVerify = androidAttr(element, "autoVerify").equals("true", ignoreCase = true),
                )
                continue
            }

            val current = filter ?: continue
            if (depth <= current.depth) continue
            when (name) {
                "action" -> if (androidAttr(element, "name") == ACTION_VIEW) current.viewAction = true
                "category" -> if (androidAttr(element, "name") == CATEGORY_BROWSABLE) current.browsable = true
                "data" -> {
                    androidAttr(element, "scheme")?.takeIf(String::isNotBlank)?.let(current.schemes::add)
                    androidAttr(element, "host")?.takeIf(String::isNotBlank)?.let(current.hosts::add)
                    androidAttr(element, "port")?.takeIf(String::isNotBlank)?.let(current.ports::add)
                    androidAttr(element, "path")?.takeIf(String::isNotBlank)?.let(current.paths::add)
                    androidAttr(element, "pathPrefix")?.takeIf(String::isNotBlank)?.let(current.pathPrefixes::add)
                    androidAttr(element, "pathPattern")?.takeIf(String::isNotBlank)?.let(current.pathPatterns::add)
                    androidAttr(element, "mimeType")?.takeIf(String::isNotBlank)?.let(current.mimeTypes::add)
                }
            }
        }
        finishFilter()
        return results.distinct().sortedWith(compareBy({ it.componentName }, { it.schemes.joinToString() }, { it.hosts.joinToString() }))
    }


    private fun parseProviders(elements: JSONArray): List<ProviderDeclaration> {
        val out = mutableListOf<ProviderDeclaration>()
        var state: ProviderState? = null
        fun finish() {
            val p = state ?: return
            out += ProviderDeclaration(
                name = p.name, authorities = p.authorities.toSortedSet().toList(), exported = p.exported,
                grantUriPermissions = p.grantUriPermissions, readPermission = p.readPermission, writePermission = p.writePermission,
                pathPermissions = p.pathPermissions.distinct().sortedWith(compareBy({ it.path ?: "" }, { it.pathPrefix ?: "" }, { it.pathPattern ?: "" })),
            )
            state = null
        }
        for (i in 0 until elements.length()) {
            val element = elements.getJSONObject(i)
            val depth = element.optInt("depth", -1)
            val name = element.optString("name")
            if (state != null && depth <= state!!.depth) finish()
            if (name == "provider") {
                finish()
                val permission = androidAttr(element, "permission")
                state = ProviderState(
                    depth = depth,
                    name = androidAttr(element, "name") ?: "<unnamed-provider>",
                    authorities = androidAttr(element, "authorities").orEmpty().split(';').map { it.trim() }.filter { it.isNotEmpty() }.toMutableList(),
                    exported = androidAttr(element, "exported")?.let { it.equals("true", true) },
                    grantUriPermissions = androidAttr(element, "grantUriPermissions").equals("true", true),
                    readPermission = androidAttr(element, "readPermission") ?: permission,
                    writePermission = androidAttr(element, "writePermission") ?: permission,
                )
                continue
            }
            val current = state ?: continue
            if (depth <= current.depth || name != "path-permission") continue
            val permission = androidAttr(element, "permission")
            current.pathPermissions += ProviderPathPermissionSummary(
                path = androidAttr(element, "path"), pathPrefix = androidAttr(element, "pathPrefix"),
                pathPattern = androidAttr(element, "pathPattern"), readPermission = androidAttr(element, "readPermission") ?: permission,
                writePermission = androidAttr(element, "writePermission") ?: permission,
            )
        }
        finish()
        return out.distinct().sortedBy { it.name }
    }
    private fun androidAttr(element: JSONObject, name: String): String? {
        val attrs = element.optJSONArray("attributes") ?: return null
        for (i in 0 until attrs.length()) {
            val attr = attrs.getJSONObject(i)
            if (attr.optString("name") != name) continue
            val ns = if (attr.isNull("namespace")) null else attr.optString("namespace")
            if (ns == null || ns == ANDROID_NS) return attr.optString("value", "")
        }
        return null
    }

    private data class IntentFilterState(
        val componentName: String,
        val depth: Int,
        val autoVerify: Boolean,
        var viewAction: Boolean = false,
        var browsable: Boolean = false,
        val schemes: MutableList<String> = mutableListOf(),
        val hosts: MutableList<String> = mutableListOf(),
        val ports: MutableList<String> = mutableListOf(),
        val paths: MutableList<String> = mutableListOf(),
        val pathPrefixes: MutableList<String> = mutableListOf(),
        val pathPatterns: MutableList<String> = mutableListOf(),
        val mimeTypes: MutableList<String> = mutableListOf(),
    )

    private data class ProviderState(
        val depth: Int, val name: String, val authorities: MutableList<String>, val exported: Boolean?,
        val grantUriPermissions: Boolean, val readPermission: String?, val writePermission: String?,
        val pathPermissions: MutableList<ProviderPathPermissionSummary> = mutableListOf(),
    )

    private val COMPONENT_NAMES = setOf("activity", "activity-alias")
}
