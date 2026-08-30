package org.unirevlab.security.analysis

import org.unirevlab.security.model.DependencyComponentSummary
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.RuntimeArtifactSummary
import org.unirevlab.security.model.SupplyChainSummary
import java.io.File
import java.util.Properties
import java.util.zip.ZipFile

/** Passive component fingerprinting. Versions are reported only when supported by explicit evidence. */
object SupplyChainScanner {
    data class Limits(
        val maxComponents: Int = 256,
        val maxNativeDependencies: Int = 512,
        val maxPomProperties: Int = 128,
        val maxPomBytes: Long = 64L * 1024L,
        val maxManagedAssemblyRefs: Int = 128,
    )

    private data class Marker(val prefix: String, val id: String, val name: String, val ecosystem: String)
    private val dexMarkers = listOf(
        Marker("Lokhttp3/", "maven:com.squareup.okhttp3:okhttp", "OkHttp", "MAVEN"),
        Marker("Lretrofit2/", "maven:com.squareup.retrofit2:retrofit", "Retrofit", "MAVEN"),
        Marker("Lcom/google/gson/", "maven:com.google.code.gson:gson", "Gson", "MAVEN"),
        Marker("Lkotlinx/coroutines/", "maven:org.jetbrains.kotlinx:kotlinx-coroutines-core", "Kotlin Coroutines", "MAVEN"),
        Marker("Lcom/google/firebase/", "maven:com.google.firebase", "Firebase Android SDK", "MAVEN"),
        Marker("Lcom/facebook/react/", "npm:react-native", "React Native", "NPM/RUNTIME"),
        Marker("Lorg/apache/cordova/", "npm:cordova-android", "Cordova Android", "NPM/RUNTIME"),
        Marker("Landroidx/", "maven:androidx", "AndroidX", "MAVEN"),
    )

    fun scan(
        apk: File?,
        dex: DexSummary?,
        native: NativeSummary?,
        il2cpp: Il2CppSummary?,
        runtime: RuntimeArtifactSummary?,
        limits: Limits = Limits(),
        archiveIndex: ApkArchiveIndex? = null,
    ): SupplyChainSummary {
        val components = linkedMapOf<String, DependencyComponentSummary>()
        fun score(c: DependencyComponentSummary): Int = (if (c.version != null) 100 else 0) + when (c.confidence) {
            "HIGH" -> 30; "MEDIUM" -> 20; else -> 10
        }
        fun add(c: DependencyComponentSummary) {
            val old = components[c.id]
            if (old == null) {
                if (components.size < limits.maxComponents) components[c.id] = c
            } else if (score(c) > score(old)) {
                components[c.id] = c.copy(evidence = (old.evidence + c.evidence).distinct().take(16))
            } else {
                components[c.id] = old.copy(evidence = (old.evidence + c.evidence).distinct().take(16))
            }
        }

        val markerHits = Array(dexMarkers.size) { ArrayList<String>(4) }
        var unresolvedMarkers = dexMarkers.size
        for (clazz in dex?.classes.orEmpty()) {
            if (unresolvedMarkers == 0) break
            val descriptor = clazz.descriptor
            for (index in dexMarkers.indices) {
                val hits = markerHits[index]
                if (hits.size >= 4) continue
                if (descriptor.startsWith(dexMarkers[index].prefix)) {
                    hits += descriptor
                    if (hits.size == 4) unresolvedMarkers--
                }
            }
        }
        dexMarkers.forEachIndexed { index, marker ->
            val hits = markerHits[index]
            if (hits.isNotEmpty()) add(DependencyComponentSummary(marker.id, marker.name, marker.ecosystem, confidence = "MEDIUM", evidence = hits))
        }

        apk?.takeIf { it.isFile }?.let { scanMavenPomProperties(it, limits, archiveIndex).forEach(::add) }

        runtime?.flutter?.takeIf { it.detected }?.let {
            add(DependencyComponentSummary("runtime:flutter", "Flutter", "DART/RUNTIME", confidence = it.confidence, evidence = (it.flutterLibraries + it.appLibraries).take(8)))
        }
        runtime?.hermes?.takeIf { it.detected }?.let {
            add(DependencyComponentSummary("runtime:hermes", "Hermes", "JS/RUNTIME", confidence = it.confidence, evidence = (it.hermesLibraries + it.bytecodeFiles.map { b -> b.entryName }).take(8)))
        }
        runtime?.unityMono?.takeIf { it.detected }?.let { mono ->
            add(DependencyComponentSummary("runtime:unity-mono", "Unity Mono", "UNITY/RUNTIME", confidence = mono.confidence, evidence = (mono.unityLibraries + mono.monoLibraries + mono.assemblies.map { a -> a.entryName }).take(8)))
            val seenAssemblyRefs = HashSet<Pair<String, String>>()
            var reportedAssemblyRefs = 0
            assemblyLoop@ for (assembly in mono.assemblies) {
                for (ref in assembly.assemblyReferences) {
                    if (!seenAssemblyRefs.add(ref.name to ref.version)) continue
                    if (reportedAssemblyRefs >= limits.maxManagedAssemblyRefs) break@assemblyLoop
                    reportedAssemblyRefs++
                    val id = "dotnet-assembly:${ref.name.lowercase()}@${ref.version}"
                    add(DependencyComponentSummary(
                        id = id,
                        name = ref.name,
                        ecosystem = "DOTNET/ASSEMBLY",
                        version = ref.version,
                        confidence = "HIGH",
                        evidence = listOf("${assembly.entryName} AssemblyRef#${ref.index}"),
                        versionEvidence = "ECMA-335 AssemblyRef version fields",
                    ))
                }
            }
        }
        runtime?.unreal?.takeIf { it.detected }?.let {
            add(DependencyComponentSummary("runtime:unreal", "Unreal Engine", "UNREAL/RUNTIME", confidence = it.confidence, evidence = (it.engineLibraries + it.containers.map { c -> c.entryName }).take(8)))
        }
        il2cpp?.takeIf { it.detected }?.let {
            val unityVersion = it.metadata?.unityVersionCandidates?.firstOrNull()
            add(DependencyComponentSummary(
                "runtime:unity-il2cpp", "Unity IL2CPP", "UNITY/RUNTIME",
                version = unityVersion,
                confidence = it.confidence,
                evidence = (it.libil2cppLibraries + listOfNotNull(it.metadata?.entryName)).take(8),
                versionEvidence = unityVersion?.let { _ -> "Unity version marker from packaged Unity data/metadata" },
            ))
        }

        val nativeDeps = java.util.TreeSet<String>().apply {
            native?.libraries.orEmpty().forEach { addAll(it.neededLibraries) }
        }.toList()
        val truncated = components.size >= limits.maxComponents || nativeDeps.size > limits.maxNativeDependencies
        return SupplyChainSummary(components = components.values.sortedBy { it.id }, nativeDependencies = nativeDeps.take(limits.maxNativeDependencies), truncated = truncated)
    }

    private fun scanMavenPomProperties(apk: File, limits: Limits, archiveIndex: ApkArchiveIndex?): List<DependencyComponentSummary> {
        val out = mutableListOf<DependencyComponentSummary>()
        runCatching {
            ZipFile(apk).use { zip ->
                val entries = if (archiveIndex != null && !archiveIndex.duplicateMavenPomNames && limits.maxPomProperties <= 128) {
                    archiveIndex.mavenPomEntries.asSequence().take(limits.maxPomProperties).mapNotNull { zip.getEntry(it.name) }.toList()
                } else {
                    zip.entries().asSequence()
                        .filter { !it.isDirectory && it.name.startsWith("META-INF/maven/") && it.name.endsWith("/pom.properties") }
                        .take(limits.maxPomProperties)
                        .toList()
                }
                for (entry in entries) {
                    if (entry.size < 0 || entry.size > limits.maxPomBytes) continue
                    val props = Properties()
                    zip.getInputStream(entry).use { props.load(it) }
                    val group = props.getProperty("groupId")?.trim().orEmpty()
                    val artifact = props.getProperty("artifactId")?.trim().orEmpty()
                    val version = props.getProperty("version")?.trim().orEmpty()
                    if (group.isBlank() || artifact.isBlank() || version.isBlank()) continue
                    val id = "maven:$group:$artifact"
                    out += DependencyComponentSummary(
                        id = id,
                        name = artifact,
                        ecosystem = "MAVEN",
                        version = version,
                        purl = "pkg:maven/${purlEncode(group)}/${purlEncode(artifact)}@${purlEncode(version)}",
                        confidence = "HIGH",
                        evidence = listOf(entry.name),
                        versionEvidence = "META-INF/maven pom.properties",
                    )
                }
            }
        }
        return out.distinctBy { it.id to it.version }
    }

    private fun purlEncode(value: String): String = buildString {
        value.forEach { c ->
            if (c.isLetterOrDigit() || c in "._-~") append(c)
            else c.toString().toByteArray(Charsets.UTF_8).forEach { b -> append("%%%02X".format(b.toInt() and 0xff)) }
        }
    }
}
