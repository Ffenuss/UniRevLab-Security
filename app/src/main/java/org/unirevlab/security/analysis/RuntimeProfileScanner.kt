package org.unirevlab.security.analysis

import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.RuntimeProfileDetection
import org.unirevlab.security.model.RuntimeSummary
import java.io.File
import java.util.zip.ZipFile

object RuntimeProfileScanner {
    data class SharedEvidence(
        val classesLower: Set<String>,
        val libraryEntriesLower: List<String>,
    )

    fun prepareSharedEvidence(dex: DexSummary?, native: NativeSummary?): SharedEvidence = SharedEvidence(
        classesLower = dex?.classes.orEmpty().asSequence().map { it.descriptor.lowercase() }.toSet(),
        libraryEntriesLower = native?.libraries.orEmpty().map { it.entryName.lowercase() },
    )

    fun scanApk(
        apk: File,
        dex: DexSummary?,
        native: NativeSummary?,
        il2cpp: Il2CppSummary?,
        sharedEvidence: SharedEvidence? = null,
        archiveIndex: ApkArchiveIndex? = null,
    ): RuntimeSummary? {
        val entries = archiveIndex?.runtimeProfileEntryNamesLower ?: runCatching {
            ZipFile(apk).use { z -> z.entries().asSequence().take(100_000).filterNot { it.isDirectory }.map { it.name.lowercase() }.toSet() }
        }.getOrDefault(emptySet())
        val shared = sharedEvidence ?: prepareSharedEvidence(dex, native)
        val classes = shared.classesLower
        val libs = shared.libraryEntriesLower
        val profiles = mutableListOf<RuntimeProfileDetection>()
        fun add(kind:String, indicators:List<String>) { val x=indicators.distinct(); if(x.isNotEmpty()) profiles += RuntimeProfileDetection(kind, if(x.size>=2) "HIGH" else "MEDIUM", x.take(16)) }
        if (il2cpp?.detected == true) add("UNITY_IL2CPP", buildList { add("global-metadata/libil2cpp"); il2cpp.metadata?.metadataVersion?.let{add("metadata-version:$it")}; il2cpp.metadata?.layoutProfile?.let{add(it)} })
        if (il2cpp?.detected != true) {
            val monoIndicators = buildList {
                if (libs.any { it.contains("libmono") || it.contains("monosgen") }) add("libmono")
                if (entries.any { it.contains("/managed/") && it.endsWith(".dll") }) add("managed-dlls")
            }
            // libunity.so is shared by Mono and IL2CPP players and therefore cannot identify
            // Unity Mono on its own. It is retained only as supporting evidence.
            if (monoIndicators.isNotEmpty()) {
                add("UNITY_MONO", monoIndicators + if (libs.any { it.endsWith("libunity.so") }) listOf("libunity.so") else emptyList())
            }
        }
        add("UNREAL_ENGINE", buildList { if(libs.any{it.endsWith("libue4.so")||it.endsWith("libunreal.so")}) add("unreal-native"); if(entries.any{it.endsWith(".pak")&&it.contains("paks")}) add("pak-assets") })
        add("FLUTTER", buildList { if(libs.any{it.endsWith("libflutter.so")}) add("libflutter.so"); if(libs.any{it.endsWith("libapp.so")}) add("libapp.so"); if(entries.any{it.contains("flutter_assets/")}) add("flutter_assets"); if(classes.any{it.contains("io/flutter/")}) add("flutter-java") })
        val reactNativeIndicators = buildList { if(libs.any{it.contains("libreactnative")}) add("react-native-native"); if(entries.any{it.endsWith("index.android.bundle")||it.endsWith("index.android.bundle.hbc")}) add("js-bundle"); if(classes.any{it.contains("com/facebook/react/")}) add("react-native-java") }
        val hermesIndicators = buildList { if(libs.any{it.contains("libhermes")}) add("libhermes"); if(entries.any{it.endsWith(".hbc")||it.endsWith("index.android.bundle.hbc")}) add("hbc-container") }
        add("REACT_NATIVE", reactNativeIndicators)
        add("HERMES", hermesIndicators)
        if (reactNativeIndicators.isNotEmpty() && hermesIndicators.isNotEmpty()) add("REACT_NATIVE_HERMES", reactNativeIndicators + hermesIndicators)
        add("XAMARIN_DOTNET", buildList { if(libs.any{it.contains("monodroid")||it.contains("xamarin")||it.contains("monosgen")}) add("dotnet-native"); if(entries.any{it.startsWith("assemblies/")&&it.endsWith(".dll")}) add("managed-assemblies"); if(classes.any{it.contains("microsoft/maui/")||it.contains("mono/android/")}) add("dotnet-java-bridge") })
        add("CORDOVA_WEBVIEW", buildList { if(entries.any{it.endsWith("assets/www/cordova.js")||it.endsWith("www/cordova.js")}) add("cordova.js"); if(classes.any{it.contains("org/apache/cordova/")}) add("cordova-java") })
        return profiles.takeIf { it.isNotEmpty() }?.let { RuntimeSummary(it.sortedBy { p -> p.kind }) }
    }
}
