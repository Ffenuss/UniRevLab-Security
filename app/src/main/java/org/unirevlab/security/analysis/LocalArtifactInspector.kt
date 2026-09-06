package org.unirevlab.security.analysis

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.ComponentExposure
import org.unirevlab.security.model.DeclaredPermission
import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexNativeMethodDeclaration
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.DexTypeXref
import org.unirevlab.security.model.DexInvokeObservation
import org.unirevlab.security.model.DexStringXref
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodCodeReference
import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexBasicBlock
import org.unirevlab.security.model.DexConstantReference
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.RuntimeSummary
import org.unirevlab.security.model.RuntimeProfileDetection
import org.unirevlab.security.model.RuntimeArtifactSummary
import org.unirevlab.security.model.FlutterRuntimeSummary
import org.unirevlab.security.model.HermesRuntimeSummary
import org.unirevlab.security.model.UnityMonoRuntimeSummary
import org.unirevlab.security.model.UnrealRuntimeSummary
import org.unirevlab.security.model.SupplyChainSummary
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.NetworkSecurityConfigSummary
import org.unirevlab.security.model.StaticAnalysisReport
import org.unirevlab.security.model.SigningCertificateSummary
import org.unirevlab.security.nativecore.NativeAnalysis
import java.io.File
import java.io.FileOutputStream
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.CancellationException
import java.util.zip.ZipException
import java.util.zip.ZipFile

data class InspectionProgress(
    val stage: String,
    val progress: Int,
    val message: String,
    val current: Int? = null,
    val total: Int? = null,
)

class InspectionControl(
    private val progressSink: (InspectionProgress) -> Unit = {},
    private val cancelled: () -> Boolean = { false },
) {
    fun update(stage: String, progress: Int, message: String, current: Int? = null, total: Int? = null) {
        ensureActive()
        progressSink(InspectionProgress(stage, progress.coerceIn(0, 100), message, current, total))
    }

    fun ensureActive() {
        if (cancelled() || Thread.currentThread().isInterrupted) throw CancellationException("Анализ отменён пользователем")
    }
}

class LocalArtifactInspector(
    private val context: Context,
) {
    private val contentResolver = context.contentResolver
    private val cacheDir = context.cacheDir
    private val resultCache = AnalysisResultCache(File(cacheDir, "normalized-analysis-cache"), ENGINE_VERSION)

    fun inspect(
        uri: Uri,
        scope: AssessmentScope,
        control: InspectionControl = InspectionControl(),
    ): StaticAnalysisReport {
        control.update("preparing", 4, "Проверка выбранного файла")
        val metadata = queryMetadata(uri)
        metadata.second?.let { size ->
            require(size <= MAX_ARTIFACT_BYTES) {
                "Артефакт превышает локальный лимит ${MAX_ARTIFACT_BYTES / (1024 * 1024)} MiB"
            }
        }

        val temp = File.createTempFile("unirevlab-artifact-", ".apk", cacheDir)
        return try {
            control.update("preparing", 6, "Копирование и SHA-256 выбранного файла")
            val digest = copyToBoundedTempAndHash(uri, temp, control)
            val displayName = metadata.first ?: "artifact"
            val sizeBytes = metadata.second ?: temp.length()
            resultCache.load(digest)?.let { cached ->
                control.update("report", 88, "Результат найден в защищённом локальном кэше")
                return rebindCachedReport(
                    cached, scope, displayName, sizeBytes, digest,
                    sourceKind = "FILE", sourcePackageName = null, sourceInstallerPackageName = null, splitApkCount = 0,
                )
            }
            inspectPreparedFile(
                apk = temp,
                scope = scope,
                displayName = displayName,
                sizeBytes = sizeBytes,
                sha256 = digest,
                control = control,
            ).also(resultCache::store)
        } finally {
            temp.delete()
        }
    }

    /**
     * Analyze an application already installed on this Android device without launching it.
     * Base and split APKs are all included in DEX/native/runtime/SBOM analysis.
     */
    fun inspectInstalledApp(
        app: InstalledAppDescriptor,
        scope: AssessmentScope,
        control: InspectionControl = InspectionControl(),
    ): StaticAnalysisReport {
        control.update("preparing", 4, "Проверка APK-набора ${app.label}")
        val files = (listOf(app.baseApkPath) + app.splitApkPaths).map(::File)
        require(files.isNotEmpty() && files.first().isFile) { "Base APK установленного приложения недоступен" }
        require(files.all { it.isFile && it.canRead() }) { "Один или несколько APK установленного приложения недоступны для чтения" }
        val totalSize = files.sumOf { it.length() }
        require(totalSize <= MAX_INSTALLED_APK_SET_BYTES) {
            "Набор APK приложения превышает локальный лимит ${MAX_INSTALLED_APK_SET_BYTES / (1024 * 1024)} MiB"
        }

        val aggregateHash = aggregateInstalledHash(app.packageName, files, control)
        resultCache.load(aggregateHash)?.let { cached ->
            control.update("report", 88, "Результат найден в защищённом локальном кэше")
            return rebindCachedReport(
                cached, scope, "${app.label} (${app.packageName})", totalSize, aggregateHash,
                sourceKind = "INSTALLED_APP", sourcePackageName = app.packageName,
                sourceInstallerPackageName = app.installerPackageName, splitApkCount = app.splitApkPaths.size,
            )
        }
        val session = AnalysisSession()
        control.update("archive", 10, "Индекс APK и split-пакетов")
        val archiveIndexes = files.mapIndexed { index, file ->
            control.ensureActive()
            control.update("archive", 10 + ((index + 1) * 6 / files.size.coerceAtLeast(1)), "Архив ${index + 1} из ${files.size}", index + 1, files.size)
            ApkArchiveIndex.build(file)
        }
        val stats = files.mapIndexed { index, file -> archiveIndexes[index]?.let(::archiveStatsFromIndex) ?: inspectArchiveCentralDirectory(file) }
        val archive = aggregateArchiveStats(stats)
        val base = files.first()
        val baseStats = stats.firstOrNull()
        val axmlOverlay = if (baseStats?.hasAndroidManifest == true) {
            readBoundedManifest(base)?.let { bytes ->
                AxmlManifestOverlayParser.parse(NativeAnalysis.tryParseAxmlJson(bytes))
                    ?: KotlinAxmlManifestParser.parse(bytes)
            }
        } else null
        control.update("manifest", 19, "Manifest, подпись и ресурсы")
        val resourceBySource = files.mapIndexedNotNull { index, file ->
            control.ensureActive()
            val source = installedEntryPrefix(index, file)
            ResourceTableResolver.scanApk(file, source)?.let { Triple(source, file, it) }
        }
        val resources = ResourceTableResolver.merge(resourceBySource.map { it.third })
        val resolvedNetworkSecurity = ResourceTableResolver.resolveReference(
            resources, axmlOverlay?.networkSecurityConfigReference
        )
        val resolvedNetworkSecurityEntry = resolvedNetworkSecurity?.fileEntry
        val networkSecurityApk = resolvedNetworkSecurity?.sourceArchive?.let { source ->
            resourceBySource.firstOrNull { it.first == source }?.second
        } ?: base
        val networkSecurity = if (axmlOverlay?.networkSecurityConfigConfigured == true) {
            NetworkSecurityConfigScanner.scan(networkSecurityApk, axmlOverlay.networkSecurityConfigReference, resolvedNetworkSecurityEntry)
        } else null
        val manifest = if (baseStats?.hasAndroidManifest == true) inspectManifest(base, axmlOverlay, networkSecurity) else null
        require(manifest == null || manifest.packageName == app.packageName) {
            "Package name base APK не совпадает с выбранным установленным приложением"
        }

        control.update("dex", 32, "Индексирование DEX")
        val dex = mergeDexSummaries(files.mapIndexedNotNull { index, file ->
            control.ensureActive()
            val count = stats.getOrNull(index)?.dexFiles ?: 0
            count.takeIf { it > 0 }?.let {
                inspectDexStrings(file, it, installedEntryPrefix(index, file), session, archiveIndexes.getOrNull(index), control)
            }
        })
        val manifestDexReachability = ManifestDexReachabilityAnalyzer.analyze(manifest, dex)
        control.update("native", 55, "Анализ native ELF и JNI")
        val nativeRaw = mergeNativeSummaries(files.mapIndexedNotNull { index, file ->
            control.ensureActive()
            val count = stats.getOrNull(index)?.nativeLibraries ?: 0
            count.takeIf { it > 0 }?.let {
                inspectNativeLibraries(file, it, installedEntryPrefix(index, file), session, archiveIndexes.getOrNull(index), control)
            }
        })
        val native = nativeRaw?.let { JniBridgeCorrelator.correlate(dex, it) }
        control.update("il2cpp", 70, "IL2CPP и runtime-метаданные")
        val il2cpp = chooseIl2Cpp(files.mapIndexedNotNull { index, file -> inspectIl2Cpp(file, native, archiveIndexes.getOrNull(index)) })
        val runtimeEvidence = RuntimeProfileScanner.prepareSharedEvidence(dex, native)
        val runtimes = mergeRuntimeSummaries(files.mapIndexedNotNull { index, file ->
            RuntimeProfileScanner.scanApk(file, dex, native, il2cpp, sharedEvidence = runtimeEvidence, archiveIndex = archiveIndexes.getOrNull(index))
        })
        val runtimeArtifacts = mergeRuntimeArtifacts(files.mapIndexedNotNull { index, file ->
            control.ensureActive()
            RuntimeArtifactScanner.scanApk(file, native, archiveIndex = archiveIndexes.getOrNull(index))
        })
        control.update("supply_chain", 81, "Компоненты и зависимости")
        val supplyChain = mergeSupplyChain(files.mapIndexed { index, file ->
            SupplyChainScanner.scan(file, dex, native, il2cpp, runtimeArtifacts, archiveIndex = archiveIndexes.getOrNull(index))
        })

        val artifact = ArtifactSummary(
            displayName = "${app.label} (${app.packageName})",
            sizeBytes = totalSize,
            sha256 = aggregateHash,
            archiveEntries = archive?.entries,
            dexFiles = archive?.dexFiles,
            nativeLibraries = archive?.nativeLibraries,
            hasAndroidManifest = archive?.hasAndroidManifest,
            suspiciousArchivePaths = archive?.suspiciousPaths,
            truncatedArchiveScan = archive?.truncated ?: false,
            sourceKind = "INSTALLED_APP",
            sourcePackageName = app.packageName,
            sourceInstallerPackageName = app.installerPackageName,
            splitApkCount = app.splitApkPaths.size,
        )
        val findings = buildList {
            if (manifest != null) addAll(ManifestRuleEngine.evaluate(manifest))
            if (dex != null) addAll(DexRuleEngine.evaluate(dex))
            if (native != null) addAll(NativeRuleEngine.evaluate(native))
            if (il2cpp != null) addAll(Il2CppRuleEngine.evaluate(il2cpp))
        }.sortedWith(compareBy({ findingSeverityOrder(it.severity) }, { it.id }))
        control.update("report", 88, "Формирование результатов")
        val report = StaticAnalysisReport(
            engineVersion = ENGINE_VERSION,
            assessment = scope,
            artifact = artifact,
            manifest = manifest,
            resources = resources,
            dex = dex,
            native = native,
            il2cpp = il2cpp,
            manifestDexReachability = manifestDexReachability,
            runtimes = runtimes,
            runtimeArtifacts = runtimeArtifacts,
            supplyChain = supplyChain,
            findings = findings,
        )
        resultCache.store(report)
        return report
    }

    private fun rebindCachedReport(
        cached: StaticAnalysisReport,
        scope: AssessmentScope,
        displayName: String,
        sizeBytes: Long,
        sha256: String,
        sourceKind: String,
        sourcePackageName: String?,
        sourceInstallerPackageName: String?,
        splitApkCount: Int,
    ): StaticAnalysisReport = cached.copy(
        assessment = scope,
        artifact = cached.artifact.copy(
            displayName = displayName,
            sizeBytes = sizeBytes,
            sha256 = sha256,
            sourceKind = sourceKind,
            sourcePackageName = sourcePackageName,
            sourceInstallerPackageName = sourceInstallerPackageName,
            splitApkCount = splitApkCount,
        ),
    )

    private fun installedEntryPrefix(index: Int, file: File): String =
        if (index == 0) "base.apk" else "split:${file.name}"


    private fun mergeDexSummaries(values: List<DexSummary>): DexSummary? {
        if (values.isEmpty()) return null
        var truncated = values.any { it.truncated }

        val classes = BoundedCollector<DexClassReference>(MAX_REPORTED_DEX_CLASSES)
        val methods = BoundedCollector<DexMethodReference>(MAX_REPORTED_DEX_METHODS)
        val nativeMethods = BoundedCollector<DexNativeMethodDeclaration>(MAX_REPORTED_NATIVE_METHODS)
        val codeMethods = BoundedCollector<DexMethodCodeReference>(MAX_REPORTED_CODE_METHODS)
        val callXrefs = BoundedCollector<DexMethodCallXref>(MAX_REPORTED_CALL_XREFS)
        val stringXrefs = BoundedCollector<DexStringXref>(MAX_REPORTED_STRING_XREFS)
        val typeXrefs = BoundedCollector<DexTypeXref>(MAX_REPORTED_TYPE_XREFS)
        val fieldXrefs = BoundedCollector<DexFieldXref>(MAX_REPORTED_FIELD_XREFS)
        val basicBlocks = BoundedCollector<DexBasicBlock>(MAX_REPORTED_BASIC_BLOCKS)
        val constants = BoundedCollector<DexConstantReference>(MAX_REPORTED_CONSTANTS)
        val invokeObservations = BoundedCollector<DexInvokeObservation>(MAX_REPORTED_INVOKE_OBSERVATIONS)
        val httpUrls = BoundedCollector<org.unirevlab.security.model.DexStringReference>(MAX_REPORTED_URLS)
        val httpsUrls = BoundedCollector<org.unirevlab.security.model.DexStringReference>(MAX_REPORTED_URLS)
        val secrets = BoundedCollector<org.unirevlab.security.model.SecretCandidate>(MAX_REPORTED_SECRET_CANDIDATES)

        for (value in values) {
            classes.addAll(value.classes)
            methods.addAll(value.methods)
            nativeMethods.addAll(value.nativeMethods)
            codeMethods.addAll(value.codeMethods)
            callXrefs.addAll(value.callXrefs)
            stringXrefs.addAll(value.stringXrefs)
            typeXrefs.addAll(value.typeXrefs)
            fieldXrefs.addAll(value.fieldXrefs)
            basicBlocks.addAll(value.basicBlocks)
            constants.addAll(value.constants)
            invokeObservations.addAll(value.invokeObservations)
            httpUrls.addAll(value.httpUrls)
            httpsUrls.addAll(value.httpsUrls)
            secrets.addAll(value.secretCandidates)
        }
        truncated = truncated || listOf(
            classes.overflowed, methods.overflowed, nativeMethods.overflowed, codeMethods.overflowed,
            callXrefs.overflowed, stringXrefs.overflowed, typeXrefs.overflowed, fieldXrefs.overflowed,
            basicBlocks.overflowed, constants.overflowed, invokeObservations.overflowed,
            httpUrls.overflowed, httpsUrls.overflowed, secrets.overflowed,
        ).any { it }

        return DexSummary(
            dexFilesDiscovered = values.sumOf { it.dexFilesDiscovered },
            dexFilesScanned = values.sumOf { it.dexFilesScanned },
            stringsDeclared = values.sumOf { it.stringsDeclared },
            stringsScanned = values.sumOf { it.stringsScanned },
            typesDeclared = values.sumOf { it.typesDeclared },
            typesIndexed = values.sumOf { it.typesIndexed },
            classesDeclared = values.sumOf { it.classesDeclared },
            classesIndexed = values.sumOf { it.classesIndexed },
            methodsDeclared = values.sumOf { it.methodsDeclared },
            methodsIndexed = values.sumOf { it.methodsIndexed },
            classes = classes.toList(),
            methods = methods.toList(),
            nativeMethods = nativeMethods.toList(),
            codeMethods = codeMethods.toList(),
            callXrefs = callXrefs.toList(),
            stringXrefs = stringXrefs.toList(),
            typeXrefs = typeXrefs.toList(),
            fieldXrefs = fieldXrefs.toList(),
            basicBlocks = basicBlocks.toList(),
            constants = constants.toList(),
            invokeObservations = invokeObservations.toList(),
            httpUrls = httpUrls.toList(),
            httpsUrls = httpsUrls.toList(),
            secretCandidates = secrets.toList(),
            parseErrors = values.sumOf { it.parseErrors },
            truncated = truncated,
        )
    }

    private fun mergeNativeSummaries(values: List<NativeSummary>): NativeSummary? {
        if (values.isEmpty()) return null
        val libraries = BoundedDistinctCollector<NativeLibrarySummary, Pair<String, String>>(MAX_NATIVE_LIBRARIES) {
            it.entryName to (it.buildId ?: it.sizeBytes.toString())
        }
        values.forEach { libraries.addAll(it.libraries) }
        return NativeSummary(
            librariesDiscovered = values.sumOf { it.librariesDiscovered },
            librariesScanned = values.sumOf { it.librariesScanned },
            libraries = libraries.toList(),
            jniBridges = emptyList(),
            parseErrors = values.sumOf { it.parseErrors },
            truncated = values.any { it.truncated } || libraries.overflowed,
        )
    }

    private fun chooseIl2Cpp(values: List<Il2CppSummary>): Il2CppSummary? = Il2CppSummaryMerger.merge(values)

    private fun mergeRuntimeSummaries(values: List<RuntimeSummary>): RuntimeSummary? {
        if (values.isEmpty()) return null
        data class Acc(var confidence: String = "LOW", val indicators: java.util.TreeSet<String> = java.util.TreeSet())
        val byKind = java.util.TreeMap<String, Acc>()
        for (summary in values) {
            for (profile in summary.profiles) {
                val acc = byKind.getOrPut(profile.kind) { Acc() }
                if (confidenceRank(profile.confidence) > confidenceRank(acc.confidence)) acc.confidence = profile.confidence
                acc.indicators.addAll(profile.indicators)
            }
        }
        val profiles = byKind.map { (kind, acc) -> RuntimeProfileDetection(kind, acc.confidence, acc.indicators.toList()) }
        return profiles.takeIf { it.isNotEmpty() }?.let(::RuntimeSummary)
    }

    private fun mergeRuntimeArtifacts(values: List<RuntimeArtifactSummary>): RuntimeArtifactSummary? {
        if (values.isEmpty()) return null
        val flutterValues = values.asSequence().mapNotNull { it.flutter }.toList()
        val hermesValues = values.asSequence().mapNotNull { it.hermes }.toList()
        val monoValues = values.asSequence().mapNotNull { it.unityMono }.toList()
        val unrealValues = values.asSequence().mapNotNull { it.unreal }.toList()

        fun sortedStrings(source: Iterable<List<String>>): List<String> = java.util.TreeSet<String>().apply {
            source.forEach(::addAll)
        }.toList()

        val flutter = flutterValues.takeIf { it.isNotEmpty() }?.let { list ->
            val representativeAssets = BoundedDistinctCollector<org.unirevlab.security.model.RuntimeFileReference, String>(256) { it.entryName }
            val fingerprints = BoundedDistinctCollector<org.unirevlab.security.model.RuntimeArtifactFingerprint, Pair<String, String>>(256) { it.entryName to it.sha256 }
            val manifests = java.util.TreeSet<String>()
            val snapshots = java.util.TreeSet<String>()
            val kernels = java.util.TreeSet<String>()
            list.forEach { value ->
                representativeAssets.addAll(value.representativeAssets)
                fingerprints.addAll(value.artifactFingerprints)
                manifests.addAll(value.manifestEntries)
                snapshots.addAll(value.snapshotEntries)
                kernels.addAll(value.kernelBlobEntries)
            }
            FlutterRuntimeSummary(
                detected = list.any { it.detected },
                confidence = bestConfidence(list.map { it.confidence }),
                flutterLibraries = sortedStrings(list.map { it.flutterLibraries }),
                appLibraries = sortedStrings(list.map { it.appLibraries }),
                engineBuildIds = sortedStrings(list.map { it.engineBuildIds }),
                assetCount = list.sumOf { it.assetCount },
                representativeAssets = representativeAssets.toList(),
                manifestEntries = manifests.take(128),
                snapshotEntries = snapshots.take(128),
                kernelBlobEntries = kernels.take(128),
                aotLikely = list.any { it.aotLikely },
                artifactFingerprints = fingerprints.toList(),
                truncated = list.any { it.truncated },
            )
        }
        val hermes = hermesValues.takeIf { it.isNotEmpty() }?.let { list ->
            val bytecode = BoundedDistinctCollector<org.unirevlab.security.model.HermesBytecodeSummary, String>(128) { it.entryName }
            val bundles = BoundedDistinctCollector<org.unirevlab.security.model.RuntimeFileReference, String>(128) { it.entryName }
            list.forEach { value -> bytecode.addAll(value.bytecodeFiles); bundles.addAll(value.javascriptBundles) }
            HermesRuntimeSummary(
                detected = list.any { it.detected },
                confidence = bestConfidence(list.map { it.confidence }),
                hermesLibraries = sortedStrings(list.map { it.hermesLibraries }),
                bytecodeFiles = bytecode.toList(),
                javascriptBundles = bundles.toList(),
                truncated = list.any { it.truncated },
            )
        }
        val mono = monoValues.takeIf { it.isNotEmpty() }?.let { list ->
            val assemblies = BoundedDistinctCollector<org.unirevlab.security.model.ManagedAssemblySummary, String>(512) { it.entryName }
            list.forEach { assemblies.addAll(it.assemblies) }
            UnityMonoRuntimeSummary(
                detected = list.any { it.detected },
                confidence = bestConfidence(list.map { it.confidence }),
                monoLibraries = sortedStrings(list.map { it.monoLibraries }),
                unityLibraries = sortedStrings(list.map { it.unityLibraries }),
                assemblies = assemblies.toList(),
                truncated = list.any { it.truncated },
            )
        }
        val unreal = unrealValues.takeIf { it.isNotEmpty() }?.let { list ->
            val containers = BoundedDistinctCollector<org.unirevlab.security.model.UnrealContainerSummary, String>(256) { it.entryName }
            val obb = BoundedDistinctCollector<org.unirevlab.security.model.RuntimeFileReference, String>(128) { it.entryName }
            val commandLines = java.util.TreeSet<String>()
            list.forEach { value -> containers.addAll(value.containers); obb.addAll(value.obbEntries); commandLines.addAll(value.commandLineEntries) }
            UnrealRuntimeSummary(
                detected = list.any { it.detected },
                confidence = bestConfidence(list.map { it.confidence }),
                engineLibraries = sortedStrings(list.map { it.engineLibraries }),
                containers = containers.toList(),
                obbEntries = obb.toList(),
                commandLineEntries = commandLines.take(64),
                truncated = list.any { it.truncated },
            )
        }
        return RuntimeArtifactSummary(flutter = flutter, hermes = hermes, unityMono = mono, unreal = unreal)
            .takeIf { it.flutter != null || it.hermes != null || it.unityMono != null || it.unreal != null }
    }

    private fun mergeSupplyChain(values: List<SupplyChainSummary>): SupplyChainSummary? {
        if (values.isEmpty()) return null
        val bestComponents = LinkedHashMap<Pair<String, String?>, org.unirevlab.security.model.DependencyComponentSummary>()
        val nativeDeps = java.util.TreeSet<String>()
        val feeds = LinkedHashMap<String, org.unirevlab.security.model.AdvisoryFeedProvenance>()
        val vulnerabilities = LinkedHashMap<Triple<String, String, String>, org.unirevlab.security.model.VulnerabilityAdvisoryMatch>()

        for (summary in values) {
            for (component in summary.components) {
                val key = component.id to component.version
                val current = bestComponents[key]
                if (current == null ||
                    (component.version != null && current.version == null) ||
                    ((component.version != null) == (current.version != null) && confidenceRank(component.confidence) > confidenceRank(current.confidence))
                ) {
                    bestComponents[key] = component
                }
            }
            nativeDeps.addAll(summary.nativeDependencies)
            summary.advisoryFeed?.let { feeds.putIfAbsent(it.sha256, it) }
            for (vulnerability in summary.vulnerabilities) {
                vulnerabilities.putIfAbsent(Triple(vulnerability.advisoryId, vulnerability.componentId, vulnerability.componentVersion), vulnerability)
            }
        }
        val components = bestComponents.values.sortedBy { it.id }
        val vulnerabilityList = vulnerabilities.values.sortedWith(compareBy({ it.componentId }, { it.componentVersion }, { it.advisoryId }))
        return SupplyChainSummary(
            components = components.take(MAX_SUPPLY_COMPONENTS),
            nativeDependencies = nativeDeps.take(MAX_NATIVE_DEPENDENCIES),
            advisoryFeed = feeds.values.singleOrNull(),
            vulnerabilities = vulnerabilityList.take(2_000),
            truncated = values.any { it.truncated } || components.size > MAX_SUPPLY_COMPONENTS || nativeDeps.size > MAX_NATIVE_DEPENDENCIES || vulnerabilityList.size > 2_000 || feeds.size > 1,
        )
    }

    private fun bestConfidence(values: List<String>): String =
        values.maxByOrNull(::confidenceRank) ?: "LOW"

    private fun confidenceRank(value: String): Int = when (value.uppercase()) {
        "CONFIRMED" -> 4
        "HIGH" -> 3
        "MEDIUM" -> 2
        else -> 1
    }


    private fun inspectPreparedFile(
        apk: File,
        scope: AssessmentScope,
        displayName: String,
        sizeBytes: Long,
        sha256: String,
        archiveOverride: ArchiveStats? = null,
        sourceKind: String = "FILE",
        sourcePackageName: String? = null,
        sourceInstallerPackageName: String? = null,
        splitApkCount: Int = 0,
        control: InspectionControl = InspectionControl(),
    ): StaticAnalysisReport {
        val session = AnalysisSession()
        control.update("archive", 10, "Структура APK и подпись")
        val archiveIndex = ApkArchiveIndex.build(apk)
        val archive = archiveOverride ?: archiveIndex?.let(::archiveStatsFromIndex) ?: inspectArchiveCentralDirectory(apk)
        val artifact = ArtifactSummary(
            displayName = displayName,
            sizeBytes = sizeBytes,
            sha256 = sha256,
            archiveEntries = archive?.entries,
            dexFiles = archive?.dexFiles,
            nativeLibraries = archive?.nativeLibraries,
            hasAndroidManifest = archive?.hasAndroidManifest,
            suspiciousArchivePaths = archive?.suspiciousPaths,
            truncatedArchiveScan = archive?.truncated ?: false,
            sourceKind = sourceKind,
            sourcePackageName = sourcePackageName,
            sourceInstallerPackageName = sourceInstallerPackageName,
            splitApkCount = splitApkCount,
        )
        val baseArchive = archive
        control.update("manifest", 20, "Manifest и таблица ресурсов")
        val axmlOverlay = if (baseArchive?.hasAndroidManifest == true) {
            val manifestBytes = readBoundedManifest(apk)
            manifestBytes?.let { bytes ->
                AxmlManifestOverlayParser.parse(NativeAnalysis.tryParseAxmlJson(bytes))
                    ?: KotlinAxmlManifestParser.parse(bytes)
            }
        } else null
        val resources = ResourceTableResolver.scanApk(apk, "artifact.apk")
        val resolvedNetworkSecurityEntry = ResourceTableResolver.resolveReference(
            resources, axmlOverlay?.networkSecurityConfigReference
        )?.fileEntry
        val networkSecurity = if (axmlOverlay?.networkSecurityConfigConfigured == true) {
            NetworkSecurityConfigScanner.scan(apk, axmlOverlay.networkSecurityConfigReference, resolvedNetworkSecurityEntry)
        } else null
        val manifest = if (baseArchive?.hasAndroidManifest == true) inspectManifest(apk, axmlOverlay, networkSecurity) else null
        control.update("dex", 32, "Индексирование DEX")
        val dex = baseArchive?.dexFiles?.takeIf { it > 0 }?.let { inspectDexStrings(apk, it, session = session, archiveIndex = archiveIndex, control = control) }
        val manifestDexReachability = ManifestDexReachabilityAnalyzer.analyze(manifest, dex)
        control.update("native", 55, "Анализ native ELF и JNI")
        val nativeRaw = baseArchive?.nativeLibraries?.takeIf { it > 0 }?.let { inspectNativeLibraries(apk, it, session = session, archiveIndex = archiveIndex, control = control) }
        val native = nativeRaw?.let { JniBridgeCorrelator.correlate(dex, it) }
        control.update("il2cpp", 70, "IL2CPP и runtime-метаданные")
        val il2cpp = inspectIl2Cpp(apk, native, archiveIndex)
        val runtimeEvidence = RuntimeProfileScanner.prepareSharedEvidence(dex, native)
        val runtimes = RuntimeProfileScanner.scanApk(apk, dex, native, il2cpp, sharedEvidence = runtimeEvidence, archiveIndex = archiveIndex)
        val runtimeArtifacts = RuntimeArtifactScanner.scanApk(apk, native, archiveIndex = archiveIndex)
        control.update("supply_chain", 81, "Компоненты и зависимости")
        val supplyChain = SupplyChainScanner.scan(apk, dex, native, il2cpp, runtimeArtifacts, archiveIndex = archiveIndex)
        val findings = buildList {
            if (manifest != null) addAll(ManifestRuleEngine.evaluate(manifest))
            if (dex != null) addAll(DexRuleEngine.evaluate(dex))
            if (native != null) addAll(NativeRuleEngine.evaluate(native))
            if (il2cpp != null) addAll(Il2CppRuleEngine.evaluate(il2cpp))
        }.sortedWith(compareBy({ findingSeverityOrder(it.severity) }, { it.id }))
        control.update("report", 88, "Формирование результатов")
        return StaticAnalysisReport(
            engineVersion = ENGINE_VERSION,
            assessment = scope,
            artifact = artifact,
            manifest = manifest,
            resources = resources,
            dex = dex,
            native = native,
            il2cpp = il2cpp,
            manifestDexReachability = manifestDexReachability,
            runtimes = runtimes,
            runtimeArtifacts = runtimeArtifacts,
            supplyChain = supplyChain,
            findings = findings,
        )
    }

    private fun archiveStatsFromIndex(index: ApkArchiveIndex): ArchiveStats = ArchiveStats(
        entries = index.archiveEntries,
        dexFiles = index.archiveDexFiles,
        nativeLibraries = index.archiveNativeLibraries,
        hasAndroidManifest = index.archiveHasManifest,
        suspiciousPaths = index.archiveSuspiciousPaths,
        truncated = index.archiveTruncated,
    )

    private fun aggregateArchiveStats(values: List<ArchiveStats?>): ArchiveStats? {
        val stats = values.filterNotNull()
        if (stats.isEmpty()) return null
        return ArchiveStats(
            entries = stats.sumOf { it.entries },
            dexFiles = stats.sumOf { it.dexFiles },
            nativeLibraries = stats.sumOf { it.nativeLibraries },
            hasAndroidManifest = stats.any { it.hasAndroidManifest },
            suspiciousPaths = stats.sumOf { it.suspiciousPaths },
            truncated = stats.any { it.truncated },
        )
    }

    private fun aggregateInstalledHash(packageName: String, files: List<File>, control: InspectionControl): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(packageName.toByteArray(Charsets.UTF_8))
        files.forEachIndexed { index, file ->
            control.ensureActive()
            digest.update(index.toString().toByteArray(Charsets.UTF_8))
            digest.update(file.name.toByteArray(Charsets.UTF_8))
            file.inputStream().buffered().use { input ->
                val buffer = ByteArray(IO_BUFFER_BYTES)
                while (true) {
                    control.ensureActive()
                    val read = input.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                }
            }
        }
        return digest.digest().toHex()
    }


    private data class DexScanBundle(
        val sourceEntry: String,
        val inventory: DexStringScanner.FileResult,
        val code: DexCodeScanner.FileResult?,
    )

    private class AnalysisSession {
        val dexBySha256 = java.util.concurrent.ConcurrentHashMap<String, DexScanBundle>()
        val nativeBySha256 = java.util.concurrent.ConcurrentHashMap<String, NativeLibrarySummary>()
    }

    private data class CopiedEntry(val bytes: Long, val sha256: String)
    private data class PreparedDexEntry(val reportedEntry: String, val file: File, val sha256: String)
    private data class DexTaskResult(val prepared: PreparedDexEntry, val bundle: DexScanBundle?, val failed: Boolean)
    private data class PreparedNativeEntry(
        val reportedEntry: String,
        val rawEntryName: String,
        val bytes: Long,
        val file: File,
        val sha256: String,
    )
    private data class NativeTaskResult(
        val prepared: PreparedNativeEntry,
        val library: NativeLibrarySummary?,
        val errorMessage: String? = null,
    )

    private fun rebaseDexInventory(value: DexStringScanner.FileResult, dexEntry: String): DexStringScanner.FileResult = value.copy(
        classes = value.classes.map { it.copy(dexEntry = dexEntry) },
        methods = value.methods.map { it.copy(dexEntry = dexEntry) },
        nativeMethods = value.nativeMethods.map { it.copy(dexEntry = dexEntry) },
        httpUrls = value.httpUrls.map { it.copy(dexEntry = dexEntry) },
        httpsUrls = value.httpsUrls.map { it.copy(dexEntry = dexEntry) },
        secretCandidates = value.secretCandidates.map { it.copy(dexEntry = dexEntry) },
    )

    private fun rebaseDexCode(value: DexCodeScanner.FileResult, dexEntry: String): DexCodeScanner.FileResult = value.copy(
        codeMethods = value.codeMethods.map { it.copy(dexEntry = dexEntry) },
        callXrefs = value.callXrefs.map { it.copy(dexEntry = dexEntry) },
        stringXrefs = value.stringXrefs.map { it.copy(dexEntry = dexEntry) },
        typeXrefs = value.typeXrefs.map { it.copy(dexEntry = dexEntry) },
        fieldXrefs = value.fieldXrefs.map { it.copy(dexEntry = dexEntry) },
        basicBlocks = value.basicBlocks.map { it.copy(dexEntry = dexEntry) },
        constants = value.constants.map { it.copy(dexEntry = dexEntry) },
        invokeObservations = value.invokeObservations.map { it.copy(dexEntry = dexEntry) },
    )

    private fun rebaseNativeLibrary(value: NativeLibrarySummary, entryName: String): NativeLibrarySummary = value.copy(
        entryName = entryName,
        importedSymbols = value.importedSymbols.map { it.copy(libraryEntry = entryName) },
        exportedSymbols = value.exportedSymbols.map { it.copy(libraryEntry = entryName) },
        secretCandidates = value.secretCandidates.map { it.copy(libraryEntry = entryName) },
    )

    private fun obtainDexScan(reportedEntry: String, file: File, sha256: String, session: AnalysisSession): DexScanBundle {
        val canonical = session.dexBySha256.computeIfAbsent(sha256) {
            val inventory = DexStringScanner.scan(reportedEntry, file)
            val code = runCatching {
                DexCodeScanner.scan(reportedEntry, file, structuralIndex = inventory.structuralIndex)
            }.getOrNull()
            DexScanBundle(reportedEntry, inventory, code)
        }
        if (canonical.sourceEntry == reportedEntry) return canonical
        return DexScanBundle(
            sourceEntry = reportedEntry,
            inventory = rebaseDexInventory(canonical.inventory, reportedEntry),
            code = canonical.code?.let { rebaseDexCode(it, reportedEntry) },
        )
    }

    private fun inspectDexStrings(
        apk: File,
        discovered: Int,
        entryPrefix: String? = null,
        session: AnalysisSession = AnalysisSession(),
        archiveIndex: ApkArchiveIndex? = null,
        control: InspectionControl = InspectionControl(),
    ): DexSummary {
        var filesScanned = 0
        var stringsDeclared = 0L
        var stringsScanned = 0L
        var parseErrors = 0
        var truncated = false
        var typesDeclared = 0L
        var typesIndexed = 0L
        var classesDeclared = 0L
        var classesIndexed = 0L
        var methodsDeclared = 0L
        var methodsIndexed = 0L
        var totalDexBytes = 0L
        val httpUrls = BoundedDistinctCollector<org.unirevlab.security.model.DexStringReference, Triple<String, Int, String>>(MAX_REPORTED_URLS) { Triple(it.dexEntry, it.stringIndex, it.value) }
        val httpsUrls = BoundedDistinctCollector<org.unirevlab.security.model.DexStringReference, Triple<String, Int, String>>(MAX_REPORTED_URLS) { Triple(it.dexEntry, it.stringIndex, it.value) }
        val secretCandidates = BoundedDistinctCollector<org.unirevlab.security.model.SecretCandidate, Triple<String, String, Int>>(MAX_REPORTED_SECRET_CANDIDATES) { Triple(it.kind, it.dexEntry, it.stringIndex) }
        val classes = BoundedDistinctCollector<DexClassReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_CLASSES) { Triple(it.dexEntry, it.classIndex, it.descriptor) }
        val methods = BoundedDistinctCollector<DexMethodReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_METHODS) { Triple(it.dexEntry, it.methodIndex, it.declaringClass) }
        val nativeMethods = BoundedDistinctCollector<DexNativeMethodDeclaration, Triple<String, Int, String>>(MAX_REPORTED_NATIVE_METHODS) { Triple(it.dexEntry, it.methodIndex, it.declaringClass) }
        val codeMethods = BoundedDistinctCollector<DexMethodCodeReference, Triple<String, Int, Long>>(MAX_REPORTED_CODE_METHODS) { Triple(it.dexEntry, it.methodIndex, it.codeOffset) }
        val callXrefs = BoundedDistinctCollector<DexMethodCallXref, List<Any>>(MAX_REPORTED_CALL_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }
        val stringXrefs = BoundedDistinctCollector<DexStringXref, List<Any>>(MAX_REPORTED_STRING_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.stringIndex, it.instructionOffsetCodeUnits) }
        val typeXrefs = BoundedDistinctCollector<DexTypeXref, List<Any>>(MAX_REPORTED_TYPE_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.typeIndex, it.kind, it.instructionOffsetCodeUnits) }
        val fieldXrefs = BoundedDistinctCollector<DexFieldXref, List<Any>>(MAX_REPORTED_FIELD_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.fieldIndex, it.kind, it.instructionOffsetCodeUnits) }
        val basicBlocks = BoundedDistinctCollector<DexBasicBlock, List<Any>>(MAX_REPORTED_BASIC_BLOCKS) { listOf(it.dexEntry, it.methodIndex, it.startCodeUnit) }
        val constants = BoundedDistinctCollector<DexConstantReference, List<Any>>(MAX_REPORTED_CONSTANTS) { listOf(it.dexEntry, it.methodIndex, it.register, it.instructionOffsetCodeUnits) }
        val invokeObservations = BoundedDistinctCollector<DexInvokeObservation, List<Any>>(MAX_REPORTED_INVOKE_OBSERVATIONS) { listOf(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }

        try {
            ZipFile(apk).use { zip ->
                val dexEntries = if (archiveIndex != null && !archiveIndex.duplicateDexNames) {
                    archiveIndex.dexEntryNames.mapNotNull(zip::getEntry)
                } else {
                    buildList {
                        val entries = zip.entries()
                        while (entries.hasMoreElements()) {
                            val entry = entries.nextElement()
                            if (!entry.isDirectory && ArchiveClassifier.isDex(entry.name)) add(entry)
                        }
                    }.sortedBy { it.name }
                }

                val dexEntryCount = archiveIndex?.takeIf { !it.duplicateDexNames }?.dexEntryCount ?: dexEntries.size
                if (dexEntryCount > MAX_DEX_FILES) truncated = true
                val candidates = dexEntries.take(MAX_DEX_FILES)
                val executor = CPU_EXECUTOR
                run {
                    var cursor = 0
                    while (cursor < candidates.size) {
                        control.ensureActive()
                        control.update("dex", 32 + (cursor * 21 / candidates.size.coerceAtLeast(1)), "DEX ${cursor + 1} из ${candidates.size}", cursor + 1, candidates.size)
                        if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("DEX analysis cancelled")
                        if (totalDexBytes >= MAX_TOTAL_DEX_BYTES) {
                            truncated = true
                            break
                        }
                        val prepared = ArrayList<PreparedDexEntry>(DEX_PARALLELISM)
                        while (cursor < candidates.size && prepared.size < DEX_PARALLELISM) {
                            val entry = candidates[cursor++]
                            if (totalDexBytes >= MAX_TOTAL_DEX_BYTES) {
                                truncated = true
                                break
                            }
                            if (entry.size > MAX_SINGLE_DEX_BYTES) {
                                truncated = true
                                continue
                            }
                            val remainingBudget = MAX_TOTAL_DEX_BYTES - totalDexBytes
                            val perEntryLimit = minOf(MAX_SINGLE_DEX_BYTES, remainingBudget)
                            val tempDex = File.createTempFile("unirevlab-dex-", ".dex", cacheDir)
                            try {
                                val copied = copyZipEntryBoundedAndHash(zip, entry, tempDex, perEntryLimit)
                                totalDexBytes += copied.bytes
                                val reportedEntry = entryPrefix?.let { "$it!/${entry.name}" } ?: entry.name
                                prepared += PreparedDexEntry(reportedEntry, tempDex, copied.sha256)
                            } catch (_: IllegalArgumentException) {
                                truncated = true
                                tempDex.delete()
                            } catch (_: java.io.IOException) {
                                parseErrors++
                                tempDex.delete()
                            }
                        }
                        if (prepared.isEmpty()) continue

                        val futures = prepared.map { item ->
                            executor.submit(java.util.concurrent.Callable {
                                try {
                                    DexTaskResult(item, obtainDexScan(item.reportedEntry, item.file, item.sha256, session), failed = false)
                                } catch (_: Exception) {
                                    DexTaskResult(item, bundle = null, failed = true)
                                }
                            })
                        }
                        for (future in futures) {
                            val task = try {
                                future.get()
                            } catch (e: InterruptedException) {
                                Thread.currentThread().interrupt()
                                throw java.io.InterruptedIOException("DEX analysis cancelled")
                            }
                            try {
                                val bundle = task.bundle
                                if (task.failed || bundle == null) {
                                    parseErrors++
                                    continue
                                }
                                val scan = bundle.inventory
                                filesScanned++
                                stringsDeclared += scan.stringsDeclared.toLong()
                                stringsScanned += scan.stringsScanned.toLong()
                                typesDeclared += scan.typesDeclared.toLong()
                                typesIndexed += scan.typesIndexed.toLong()
                                classesDeclared += scan.classesDeclared.toLong()
                                classesIndexed += scan.classesIndexed.toLong()
                                methodsDeclared += scan.methodsDeclared.toLong()
                                methodsIndexed += scan.methodsIndexed.toLong()
                                classes.addAll(scan.classes)
                                methods.addAll(scan.methods)
                                nativeMethods.addAll(scan.nativeMethods)
                                if (scan.truncated) truncated = true
                                httpUrls.addAll(scan.httpUrls)
                                httpsUrls.addAll(scan.httpsUrls)
                                secretCandidates.addAll(scan.secretCandidates)
                                val code = bundle.code
                                if (code == null) {
                                    truncated = true
                                } else {
                                    codeMethods.addAll(code.codeMethods)
                                    callXrefs.addAll(code.callXrefs)
                                    stringXrefs.addAll(code.stringXrefs)
                                    typeXrefs.addAll(code.typeXrefs)
                                    fieldXrefs.addAll(code.fieldXrefs)
                                    basicBlocks.addAll(code.basicBlocks)
                                    constants.addAll(code.constants)
                                    invokeObservations.addAll(code.invokeObservations)
                                    if (code.truncated || code.decodeErrors > 0) truncated = true
                                }
                            } finally {
                                task.prepared.file.delete()
                            }
                        }
                    }
                }
            }
        } catch (_: ZipException) {
            parseErrors++
        } catch (_: java.io.IOException) {
            parseErrors++
        }

        return DexSummary(
            dexFilesDiscovered = discovered,
            dexFilesScanned = filesScanned,
            stringsDeclared = stringsDeclared,
            stringsScanned = stringsScanned,
            typesDeclared = typesDeclared,
            typesIndexed = typesIndexed,
            classesDeclared = classesDeclared,
            classesIndexed = classesIndexed,
            methodsDeclared = methodsDeclared,
            methodsIndexed = methodsIndexed,
            classes = classes.toList(),
            methods = methods.toList(),
            nativeMethods = nativeMethods.toList(),
            codeMethods = codeMethods.toList(),
            callXrefs = callXrefs.toList(),
            stringXrefs = stringXrefs.toList(),
            typeXrefs = typeXrefs.toList(),
            fieldXrefs = fieldXrefs.toList(),
            basicBlocks = basicBlocks.toList(),
            constants = constants.toList(),
            invokeObservations = invokeObservations.toList(),
            httpUrls = httpUrls.toList(),
            httpsUrls = httpsUrls.toList(),
            secretCandidates = secretCandidates.toList(),
            parseErrors = parseErrors,
            truncated = truncated || filesScanned < minOf(discovered, MAX_DEX_FILES) || listOf(
                classes.overflowed, methods.overflowed, nativeMethods.overflowed, codeMethods.overflowed,
                callXrefs.overflowed, stringXrefs.overflowed, typeXrefs.overflowed, fieldXrefs.overflowed,
                basicBlocks.overflowed, constants.overflowed, invokeObservations.overflowed,
                httpUrls.overflowed, httpsUrls.overflowed, secretCandidates.overflowed,
            ).any { it },
        )
    }

    private fun inspectIl2Cpp(apk: File, native: NativeSummary?, archiveIndex: ApkArchiveIndex? = null): Il2CppSummary? =
        Il2CppScanner.scanApk(
            apk, native,
            archiveEntryNames = archiveIndex
                ?.takeUnless { it.runtimeArtifactTruncated }
                ?.let { index -> (index.runtimeArtifactEntries.map { it.name } + index.nativeEntryNames).distinct() },
        )

    private fun inspectNativeLibraries(
        apk: File,
        discovered: Int,
        entryPrefix: String? = null,
        session: AnalysisSession = AnalysisSession(),
        archiveIndex: ApkArchiveIndex? = null,
        control: InspectionControl = InspectionControl(),
    ): NativeSummary {
        var filesScanned = 0
        var parseErrors = 0
        var truncated = false
        var totalNativeBytes = 0L
        val libraries = mutableListOf<NativeLibrarySummary>()

        fun failureLibrary(item: PreparedNativeEntry, message: String): NativeLibrarySummary = NativeLibrarySummary(
            entryName = item.reportedEntry,
            abi = item.rawEntryName.substringAfter("lib/", "unknown").substringBefore('/', "unknown"),
            elfClass = "UNKNOWN",
            machine = "UNKNOWN",
            fileType = "UNKNOWN",
            sizeBytes = item.bytes,
            buildId = null,
            neededLibraries = emptyList(),
            importedSymbols = emptyList(),
            exportedSymbols = emptyList(),
            jniSymbols = emptyList(),
            hasJniOnLoad = false,
            registerNativesIndicator = false,
            executableStack = null,
            hasGnuRelro = false,
            bindNow = false,
            hasStackCanaryImport = false,
            stripped = null,
            httpUrls = emptyList(),
            parseError = message.take(256),
        )

        try {
            ZipFile(apk).use { zip ->
                val nativeEntries = if (archiveIndex != null && !archiveIndex.duplicateNativeNames) {
                    archiveIndex.nativeEntryNames.mapNotNull(zip::getEntry)
                } else {
                    buildList {
                        val entries = zip.entries()
                        while (entries.hasMoreElements()) {
                            val entry = entries.nextElement()
                            if (!entry.isDirectory && ArchiveClassifier.isNativeLibrary(entry.name)) add(entry)
                        }
                    }.sortedBy { it.name }
                }
                val nativeEntryCount = archiveIndex?.takeIf { !it.duplicateNativeNames }?.nativeEntryCount ?: nativeEntries.size
                if (nativeEntryCount > MAX_NATIVE_LIBRARIES) truncated = true
                val selected = nativeEntries.take(MAX_NATIVE_LIBRARIES)
                var cursor = 0
                while (cursor < selected.size) {
                    control.ensureActive()
                    control.update("native", 55 + (cursor * 14 / selected.size.coerceAtLeast(1)), "Native ${cursor + 1} из ${selected.size}", cursor + 1, selected.size)
                    if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("Native analysis cancelled")
                    val prepared = ArrayList<PreparedNativeEntry>(NATIVE_PARALLELISM)
                    while (cursor < selected.size && prepared.size < NATIVE_PARALLELISM) {
                        val entry = selected[cursor++]
                        if (totalNativeBytes >= MAX_TOTAL_NATIVE_BYTES) {
                            truncated = true
                            cursor = selected.size
                            break
                        }
                        if (entry.size > MAX_SINGLE_NATIVE_BYTES) {
                            truncated = true
                            continue
                        }
                        val remainingBudget = MAX_TOTAL_NATIVE_BYTES - totalNativeBytes
                        val perEntryLimit = minOf(MAX_SINGLE_NATIVE_BYTES, remainingBudget)
                        val tempElf = File.createTempFile("unirevlab-native-", ".so", cacheDir)
                        try {
                            val copied = copyZipEntryBoundedAndHash(zip, entry, tempElf, perEntryLimit)
                            totalNativeBytes += copied.bytes
                            val reportedEntry = entryPrefix?.let { "$it!/${entry.name}" } ?: entry.name
                            val cached = session.nativeBySha256[copied.sha256]
                            if (cached != null) {
                                filesScanned++
                                libraries += rebaseNativeLibrary(cached, reportedEntry)
                                tempElf.delete()
                            } else {
                                prepared += PreparedNativeEntry(reportedEntry, entry.name, copied.bytes, tempElf, copied.sha256)
                            }
                        } catch (_: IllegalArgumentException) {
                            truncated = true
                            tempElf.delete()
                        } catch (_: java.io.IOException) {
                            parseErrors++
                            tempElf.delete()
                        }
                    }
                    if (prepared.isEmpty()) continue
                    val futures = prepared.map { item ->
                        CPU_EXECUTOR.submit(java.util.concurrent.Callable {
                            try {
                                val canonical = session.nativeBySha256.computeIfAbsent(item.sha256) {
                                    ElfNativeScanner.scan(item.reportedEntry, item.file)
                                }
                                NativeTaskResult(item, rebaseNativeLibrary(canonical, item.reportedEntry))
                            } catch (e: Exception) {
                                NativeTaskResult(item, null, e.message ?: e::class.java.simpleName)
                            }
                        })
                    }
                    for (future in futures) {
                        val task = try {
                            future.get()
                        } catch (e: InterruptedException) {
                            Thread.currentThread().interrupt()
                            throw java.io.InterruptedIOException("Native analysis cancelled")
                        }
                        try {
                            val scan = task.library
                            if (scan != null) {
                                filesScanned++
                                libraries += scan
                                if (scan.truncated) truncated = true
                            } else {
                                parseErrors++
                                libraries += failureLibrary(task.prepared, task.errorMessage ?: "native parse failed")
                            }
                        } finally {
                            task.prepared.file.delete()
                        }
                    }
                }
            }
        } catch (_: ZipException) {
            parseErrors++
        } catch (_: java.io.IOException) {
            parseErrors++
        }

        return NativeSummary(
            librariesDiscovered = discovered,
            librariesScanned = filesScanned,
            libraries = libraries,
            parseErrors = parseErrors,
            truncated = truncated || filesScanned + parseErrors < minOf(discovered, MAX_NATIVE_LIBRARIES),
        )
    }

    private fun copyZipEntryBoundedAndHash(zip: ZipFile, entry: java.util.zip.ZipEntry, destination: File, maxBytes: Long): CopiedEntry {
        var total = 0L
        val digest = MessageDigest.getInstance("SHA-256")
        zip.getInputStream(entry).use { input ->
            FileOutputStream(destination).use { output ->
                val buffer = ByteArray(IO_BUFFER_BYTES)
                while (true) {
                    if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("Analysis cancelled")
                    val read = input.read(buffer)
                    if (read <= 0) break
                    total += read
                    require(total <= maxBytes) { "Archive entry exceeds defensive decompression limit" }
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                }
            }
        }
        return CopiedEntry(total, digest.digest().toHex())
    }

    private fun findingSeverityOrder(severity: org.unirevlab.security.model.Severity): Int = when (severity) {
        org.unirevlab.security.model.Severity.CRITICAL -> 0
        org.unirevlab.security.model.Severity.HIGH -> 1
        org.unirevlab.security.model.Severity.MEDIUM -> 2
        org.unirevlab.security.model.Severity.LOW -> 3
        org.unirevlab.security.model.Severity.INFORMATIONAL -> 4
    }

    private fun copyToBoundedTempAndHash(uri: Uri, destination: File, control: InspectionControl): String {
        val digest = MessageDigest.getInstance("SHA-256")
        contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Не удалось открыть выбранный файл" }
            FileOutputStream(destination).use { fileOutput ->
                DigestOutputStream(fileOutput, digest).use { output ->
                    val buffer = ByteArray(IO_BUFFER_BYTES)
                    var total = 0L
                    while (true) {
                        control.ensureActive()
                        val read = input.read(buffer)
                        if (read <= 0) break
                        total += read
                        require(total <= MAX_ARTIFACT_BYTES) {
                            "Артефакт превышает локальный лимит ${MAX_ARTIFACT_BYTES / (1024 * 1024)} MiB"
                        }
                        output.write(buffer, 0, read)
                    }
                }
            }
        }
        return digest.digest().toHex()
    }

    private fun queryMetadata(uri: Uri): Pair<String?, Long?> {
        var name: String? = null
        var size: Long? = null
        contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
            null,
            null,
            null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (nameIndex >= 0) name = cursor.getString(nameIndex)
                if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) size = cursor.getLong(sizeIndex)
            }
        }
        return name to size
    }

    /**
     * Reads only ZIP central-directory metadata via ZipFile. Entry payloads are not decompressed,
     * which avoids turning a crafted ZIP bomb into CPU/memory amplification during this stage.
     */
    private fun inspectArchiveCentralDirectory(file: File): ArchiveStats? {
        return try {
            ZipFile(file).use { zip ->
                var entries = 0
                var dexFiles = 0
                var nativeLibraries = 0
                var hasManifest = false
                var suspiciousPaths = 0
                var truncated = false
                val iterator = zip.entries()

                while (iterator.hasMoreElements()) {
                    val entry = iterator.nextElement()
                    entries++
                    if (ArchiveClassifier.isDex(entry.name)) dexFiles++
                    if (ArchiveClassifier.isNativeLibrary(entry.name)) nativeLibraries++
                    if (entry.name == "AndroidManifest.xml") hasManifest = true
                    if (ArchiveClassifier.isSuspiciousPath(entry.name)) suspiciousPaths++
                    if (entries >= MAX_ARCHIVE_ENTRIES) {
                        truncated = iterator.hasMoreElements()
                        break
                    }
                }
                ArchiveStats(entries, dexFiles, nativeLibraries, hasManifest, suspiciousPaths, truncated)
            }
        } catch (_: ZipException) {
            null
        }
    }

    private fun readBoundedManifest(apk: File): ByteArray? {
        return try {
            ZipFile(apk).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return null
                if (entry.size > MAX_MANIFEST_BYTES) return null
                zip.getInputStream(entry).use { input ->
                    val output = java.io.ByteArrayOutputStream()
                    val buffer = ByteArray(IO_BUFFER_BYTES)
                    var total = 0
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        total += read
                        if (total > MAX_MANIFEST_BYTES) return null
                        output.write(buffer, 0, read)
                    }
                    output.toByteArray()
                }
            }
        } catch (_: Exception) {
            null
        }
    }

    @Suppress("DEPRECATION")
    private fun inspectManifest(apk: File, overlay: AxmlManifestOverlay?, networkSecurity: NetworkSecurityConfigSummary?): ManifestSummary? {
        val signingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val flags = PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            PackageManager.GET_PERMISSIONS or
            PackageManager.GET_META_DATA or
            signingFlags

        val packageInfo = context.packageManager.getPackageArchiveInfo(apk.absolutePath, flags) ?: return null
        val app = packageInfo.applicationInfo ?: return null
        val signingSchemes = ApkSigningSchemeScanner.scan(apk)

        val components = buildList {
            packageInfo.activities.orEmpty().forEach { info ->
                add(ComponentExposure("activity", info.name, info.exported, listOfNotNull(info.permission)))
            }
            packageInfo.services.orEmpty().forEach { info ->
                add(ComponentExposure("service", info.name, info.exported, listOfNotNull(info.permission)))
            }
            packageInfo.receivers.orEmpty().forEach { info ->
                add(ComponentExposure("receiver", info.name, info.exported, listOfNotNull(info.permission)))
            }
            packageInfo.providers.orEmpty().forEach { info ->
                add(
                    ComponentExposure(
                        "provider",
                        info.name,
                        info.exported,
                        listOfNotNull(info.readPermission, info.writePermission).distinct(),
                    )
                )
            }
        }

        return ManifestSummary(
            packageName = packageInfo.packageName,
            versionName = packageInfo.versionName,
            versionCode = packageInfo.longVersionCodeCompat(),
            minSdk = app.minSdkVersion,
            targetSdk = app.targetSdkVersion,
            debuggable = app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            allowBackup = app.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0,
            fullBackupContentConfigured = overlay?.fullBackupContentConfigured,
            dataExtractionRulesConfigured = overlay?.dataExtractionRulesConfigured,
            usesCleartextTraffic = app.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0,
            networkSecurityConfigConfigured = overlay?.networkSecurityConfigConfigured,
            requestedPermissions = packageInfo.requestedPermissions.orEmpty().sorted(),
            dangerousPermissions = packageInfo.requestedPermissions.orEmpty()
                .filter(::isDangerousPlatformPermission)
                .sorted(),
            declaredPermissions = packageInfo.permissions.orEmpty()
                .map { DeclaredPermission(it.name, protectionLevelName(it.protectionLevel)) }
                .sortedBy { it.name },
            components = components,
            deepLinks = overlay?.deepLinks.orEmpty(),
            providers = overlay?.providers.orEmpty(),
            signingCertificateSha256 = signingCertificateDigests(packageInfo),
            signingCertificates = signingCertificateDetails(packageInfo),
            signingSchemes = signingSchemes.schemes,
            signingBlockIds = signingSchemes.signingBlockIds,
            v1SignatureFiles = signingSchemes.v1SignatureFiles,
            signingParseError = signingSchemes.parseError,
            networkSecurity = networkSecurity,
        )
    }



    private fun protectionLevelName(protectionLevel: Int): String = when (
        protectionLevel and PermissionInfo.PROTECTION_MASK_BASE
    ) {
        PermissionInfo.PROTECTION_NORMAL -> "NORMAL"
        PermissionInfo.PROTECTION_DANGEROUS -> "DANGEROUS"
        PermissionInfo.PROTECTION_SIGNATURE -> "SIGNATURE"
        else -> "OTHER"
    }

    @Suppress("DEPRECATION")
    private fun isDangerousPlatformPermission(permission: String): Boolean {
        val info = runCatching { context.packageManager.getPermissionInfo(permission, 0) }.getOrNull() ?: return false
        return info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE == PermissionInfo.PROTECTION_DANGEROUS
    }

    @Suppress("DEPRECATION")
    private fun signingCertificateDetails(packageInfo: PackageInfo): List<SigningCertificateSummary> {
        val current = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners.orEmpty().toList()
        } else {
            packageInfo.signatures.orEmpty().toList()
        }
        val history = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = packageInfo.signingInfo
            if (info == null) emptyList() else if (info.hasMultipleSigners()) info.apkContentsSigners.orEmpty().toList() else info.signingCertificateHistory.orEmpty().toList()
        } else {
            packageInfo.signatures.orEmpty().toList()
        }
        val currentDigests = current.map { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).toHex() }.toSet()
        val certificateFactory = CertificateFactory.getInstance("X.509")
        return history.mapIndexedNotNull { index, signature ->
            runCatching {
                val encoded = signature.toByteArray()
                val sha256 = MessageDigest.getInstance("SHA-256").digest(encoded).toHex()
                val cert = certificateFactory.generateCertificate(encoded.inputStream()) as X509Certificate
                SigningCertificateSummary(
                    sha256 = sha256,
                    subjectDn = cert.subjectX500Principal?.name,
                    issuerDn = cert.issuerX500Principal?.name,
                    serialNumberHex = cert.serialNumber?.toString(16),
                    notBeforeEpochMs = cert.notBefore?.time,
                    notAfterEpochMs = cert.notAfter?.time,
                    signatureAlgorithm = cert.sigAlgName,
                    publicKeyAlgorithm = cert.publicKey?.algorithm,
                    publicKeySizeBits = publicKeySize(cert),
                    currentSigner = sha256 in currentDigests,
                    lineageIndex = if (history.size > 1) index else null,
                )
            }.getOrNull()
        }.distinctBy { it.sha256 }
    }

    private fun publicKeySize(cert: X509Certificate): Int? = when (val key = cert.publicKey) {
        is RSAPublicKey -> key.modulus.bitLength()
        is ECPublicKey -> key.params?.curve?.field?.fieldSize
        is DSAPublicKey -> key.params?.p?.bitLength()
        else -> null
    }

    @Suppress("DEPRECATION")
    private fun signingCertificateDigests(packageInfo: PackageInfo): List<String> {
        val certificates = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = packageInfo.signingInfo ?: return emptyList()
            if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners.orEmpty().toList()
            } else {
                signingInfo.signingCertificateHistory.orEmpty().toList()
            }
        } else {
            packageInfo.signatures.orEmpty().toList()
        }
        return certificates
            .map { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).toHex() }
            .distinct()
            .sorted()
    }

    @Suppress("DEPRECATION")
    private fun PackageInfo.longVersionCodeCompat(): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) longVersionCode else versionCode.toLong()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private data class ArchiveStats(
        val entries: Int,
        val dexFiles: Int,
        val nativeLibraries: Int,
        val hasAndroidManifest: Boolean,
        val suspiciousPaths: Int,
        val truncated: Boolean,
    )

    companion object {
    const val ENGINE_VERSION = "0.46.0-actionable-offset-context"
        private const val MAX_DEX_FILES = 32
        private const val MAX_SINGLE_DEX_BYTES = 96L * 1024L * 1024L
        private const val MAX_TOTAL_DEX_BYTES = 384L * 1024L * 1024L
        private const val MAX_REPORTED_URLS = 500
        private const val MAX_REPORTED_SECRET_CANDIDATES = 200
        private const val MAX_REPORTED_DEX_CLASSES = 8_000
        private const val MAX_REPORTED_DEX_METHODS = 16_000
        private const val MAX_REPORTED_NATIVE_METHODS = 4_000
        private const val MAX_REPORTED_CODE_METHODS = 20_000
        private const val MAX_REPORTED_CALL_XREFS = 100_000
        private const val MAX_REPORTED_STRING_XREFS = 60_000
        private const val MAX_REPORTED_TYPE_XREFS = 60_000
        private const val MAX_REPORTED_FIELD_XREFS = 80_000
        private const val MAX_REPORTED_BASIC_BLOCKS = 100_000
        private const val MAX_REPORTED_CONSTANTS = 60_000
        private const val MAX_REPORTED_INVOKE_OBSERVATIONS = 40_000
        private const val MAX_NATIVE_LIBRARIES = 128
        private const val MAX_SUPPLY_COMPONENTS = 512
        private const val MAX_NATIVE_DEPENDENCIES = 1024
        private const val MAX_SINGLE_NATIVE_BYTES = 128L * 1024L * 1024L
        private const val MAX_TOTAL_NATIVE_BYTES = 512L * 1024L * 1024L
        private const val MAX_ARCHIVE_ENTRIES = 20_000
        private const val MAX_MANIFEST_BYTES = 4 * 1024 * 1024
        private const val MAX_ARTIFACT_BYTES = 2L * 1024L * 1024L * 1024L
        private const val MAX_INSTALLED_APK_SET_BYTES = 4L * 1024L * 1024L * 1024L
        private const val IO_BUFFER_BYTES = 64 * 1024
        private const val DEX_PARALLELISM = 2
        private const val NATIVE_PARALLELISM = 2
        private val CPU_EXECUTOR: java.util.concurrent.ExecutorService =
            java.util.concurrent.Executors.newFixedThreadPool(DEX_PARALLELISM) { runnable ->
                Thread(runnable, "unirevlab-analysis").apply { isDaemon = true }
            }
    }
}
