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
import org.unirevlab.security.model.DexFieldReference
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
import java.io.InterruptedIOException
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.zip.ZipException
import java.util.zip.ZipFile
import java.util.concurrent.CancellationException as FutureCancellationException
import java.util.concurrent.ExecutionException

class LocalArtifactInspector(
    private val context: Context,
) {
    private val contentResolver = context.contentResolver
    private val cacheDir = context.cacheDir
    private val resultCache = AnalysisResultCache(File(cacheDir, "normalized-analysis-cache"), ENGINE_VERSION)

    private class ProgressReporter(private val callback: ((AnalysisProgress) -> Unit)?) {
        val startedAtEpochMs: Long = System.currentTimeMillis()
        private val etaEstimator = AnalysisEtaEstimator()
        private var lastPercent: Int = -1
        private var lastFraction: Double = -1.0
        private var lastStage: AnalysisStage? = null
        private var lastDetail: String? = null
        private var lastCallbackAtMs: Long = 0L

        @Synchronized
        fun emit(
            stage: AnalysisStage,
            percent: Int,
            detail: String,
            completedUnits: Int? = null,
            totalUnits: Int? = null,
            fractionComplete: Double? = null,
        ) {
            checkCancelled()
            val normalized = percent.coerceIn(0, 100)
            val normalizedFraction = (fractionComplete ?: normalized / 100.0).coerceIn(0.0, 1.0)
            if (normalized < lastPercent || (lastFraction >= 0.0 && normalizedFraction + 0.0000001 < lastFraction)) return
            val now = System.currentTimeMillis()
            val importantCheckpoint = normalized != lastPercent || stage != lastStage || normalized == 0 || normalized == 100
            if (!importantCheckpoint && now - lastCallbackAtMs < 500L) return
            lastPercent = normalized
            lastFraction = maxOf(lastFraction, normalizedFraction)
            lastStage = stage
            lastDetail = detail
            lastCallbackAtMs = now
            val finishAt = etaEstimator.observe(lastFraction, now)
            callback?.invoke(
                AnalysisProgress(
                    stage = stage,
                    percent = normalized,
                    detail = detail,
                    completedUnits = completedUnits,
                    totalUnits = totalUnits,
                    startedAtEpochMs = startedAtEpochMs,
                    updatedAtEpochMs = now,
                    fractionComplete = lastFraction,
                    estimatedFinishAtEpochMs = finishAt,
                )
            )
        }

        fun scaled(
            stage: AnalysisStage,
            fromPercent: Int,
            toPercent: Int,
            completed: Long,
            total: Long,
            detail: String,
            completedUnits: Int? = null,
            totalUnits: Int? = null,
        ) {
            val fraction = if (total <= 0L) 1.0 else (completed.toDouble() / total.toDouble()).coerceIn(0.0, 1.0)
            val precisePercent = fromPercent.toDouble() + (toPercent - fromPercent).toDouble() * fraction
            emit(
                stage, precisePercent.toInt(), detail, completedUnits, totalUnits,
                fractionComplete = precisePercent / 100.0,
            )
        }

        fun checkCancelled() = Companion.checkCancelled()
    }

    fun inspect(
        uri: Uri,
        scope: AssessmentScope,
        onProgress: ((AnalysisProgress) -> Unit)? = null,
    ): StaticAnalysisReport {
        val progress = ProgressReporter(onProgress)
        progress.emit(AnalysisStage.PREPARING, 0, "Читаем метаданные выбранного артефакта…")
        val metadata = queryMetadata(uri)
        metadata.second?.let { size ->
            require(size <= MAX_ARTIFACT_BYTES) {
                "Артефакт превышает локальный лимит ${MAX_ARTIFACT_BYTES / (1024 * 1024)} MiB"
            }
        }

        val temp = File.createTempFile("unirevlab-artifact-", ".apk", cacheDir)
        return try {
            val expectedSize = metadata.second
            progress.emit(AnalysisStage.HASHING, 1, "Копируем файл и вычисляем SHA-256…", 0, expectedSize?.coerceAtMost(Int.MAX_VALUE.toLong())?.toInt())
            val digest = copyToBoundedTempAndHash(uri, temp, expectedSize) { copied, total ->
                progress.scaled(
                    AnalysisStage.HASHING, 1, 8, copied, total ?: copied.coerceAtLeast(1L),
                    "SHA-256: прочитано ${formatBytes(copied)}${total?.let { " из ${formatBytes(it)}" } ?: ""}",
                )
            }
            val displayName = metadata.first ?: "artifact"
            val sizeBytes = metadata.second ?: temp.length()
            progress.emit(AnalysisStage.CACHE, 9, "Проверяем готовый результат по SHA-256…")
            resultCache.load(digest)?.let { cached ->
                progress.emit(AnalysisStage.COMPLETE, 100, "Готово: использован проверенный SHA-256 кэш")
                return rebindCachedReport(
                    cached, scope, displayName, sizeBytes, digest,
                    sourceKind = "FILE", sourcePackageName = null, sourceInstallerPackageName = null, splitApkCount = 0,
                )
            }
            val nestedRoot = File(cacheDir, "nested-apkset/${digest.take(24)}")
            val nested = NestedApkSet.extract(temp, nestedRoot)
            val report = if (nested != null) {
                try {
                    val baseInfo = context.packageManager.getPackageArchiveInfo(nested.base.file.absolutePath, 0)
                        ?: error("Не удалось прочитать base APK внутри контейнера")
                    val packageName = baseInfo.packageName ?: error("В base APK отсутствует packageName")
                    val descriptor = InstalledAppDescriptor(
                        label = displayName,
                        packageName = packageName,
                        versionName = baseInfo.versionName,
                        versionCode = baseInfo.longVersionCodeCompat(),
                        isSystem = false,
                        isEnabled = true,
                        baseApkPath = nested.base.file.absolutePath,
                        splitApkPaths = nested.splits.map { it.file.absolutePath },
                        installerPackageName = null,
                    )
                    val nestedReport = inspectInstalledApp(descriptor, scope) { nestedProgress ->
                        val scaled = 10 + ((nestedProgress.percent.coerceIn(0, 100) * 88) / 100)
                        val fraction = scaled / 100.0
                        onProgress?.invoke(
                            nestedProgress.copy(
                                percent = scaled,
                                fractionComplete = fraction,
                                startedAtEpochMs = progress.startedAtEpochMs,
                                detail = "APK-set: ${nestedProgress.detail}",
                            )
                        )
                    }
                    nestedReport.copy(
                        artifact = nestedReport.artifact.copy(
                            displayName = displayName,
                            sizeBytes = sizeBytes,
                            sha256 = digest,
                            sourceKind = "APK_SET_FILE",
                            sourcePackageName = packageName,
                            sourceInstallerPackageName = null,
                            splitApkCount = nested.splits.size,
                        )
                    )
                } finally {
                    nested.cleanup()
                }
            } else {
                inspectPreparedFile(
                    apk = temp,
                    scope = scope,
                    displayName = displayName,
                    sizeBytes = sizeBytes,
                    sha256 = digest,
                    progress = progress,
                )
            }
            progress.emit(AnalysisStage.SAVING, 99, "Сохраняем нормализованный результат в локальный SHA-256 кэш…")
            resultCache.store(report)
            progress.emit(AnalysisStage.COMPLETE, 100, "Анализ завершён")
            report
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
        onProgress: ((AnalysisProgress) -> Unit)? = null,
    ): StaticAnalysisReport {
        val progress = ProgressReporter(onProgress)
        progress.emit(AnalysisStage.PREPARING, 0, "Готовим base.apk и split APK установленного приложения…")
        val files = (listOf(app.baseApkPath) + app.splitApkPaths).map(::File)
        require(files.isNotEmpty() && files.first().isFile) { "Base APK установленного приложения недоступен" }
        require(files.all { it.isFile && it.canRead() }) { "Один или несколько APK установленного приложения недоступны для чтения" }
        val totalSize = files.sumOf { it.length() }
        require(totalSize <= MAX_INSTALLED_APK_SET_BYTES) {
            "Набор APK приложения превышает локальный лимит ${MAX_INSTALLED_APK_SET_BYTES / (1024 * 1024)} MiB"
        }

        progress.emit(AnalysisStage.HASHING, 1, "Вычисляем общий SHA-256 base + ${app.splitApkPaths.size} split APK…", 0, files.size)
        val aggregateHash = aggregateInstalledHash(app.packageName, files, progress)
        progress.emit(AnalysisStage.CACHE, 9, "Проверяем готовый результат по SHA-256…")
        resultCache.load(aggregateHash)?.let { cached ->
            progress.emit(AnalysisStage.COMPLETE, 100, "Готово: использован проверенный SHA-256 кэш")
            return rebindCachedReport(
                cached, scope, "${app.label} (${app.packageName})", totalSize, aggregateHash,
                sourceKind = "INSTALLED_APP", sourcePackageName = app.packageName,
                sourceInstallerPackageName = app.installerPackageName, splitApkCount = app.splitApkPaths.size,
            )
        }

        val session = AnalysisSession()
        val archiveIndexes = ArrayList<ApkArchiveIndex?>(files.size)
        progress.emit(AnalysisStage.ARCHIVE, 10, "Индексируем ZIP central directory…", 0, files.size)
        files.forEachIndexed { index, file ->
            progress.checkCancelled()
            archiveIndexes += ApkArchiveIndex.build(file)
            progress.scaled(
                AnalysisStage.ARCHIVE, 10, 14, (index + 1).toLong(), files.size.toLong(),
                "APK index: ${file.name}", index + 1, files.size,
            )
        }
        val stats = files.mapIndexed { index, file -> archiveIndexes[index]?.let(::archiveStatsFromIndex) ?: inspectArchiveCentralDirectory(file) }
        val archive = aggregateArchiveStats(stats)
        val base = files.first()
        val baseStats = stats.firstOrNull()

        progress.emit(AnalysisStage.MANIFEST, 15, "Читаем AndroidManifest.xml и resource table…")
        val axmlOverlay = if (baseStats?.hasAndroidManifest == true) {
            readBoundedManifest(base)?.let { bytes ->
                AxmlManifestOverlayParser.parse(NativeAnalysis.tryParseAxmlJson(bytes))
                    ?: KotlinAxmlManifestParser.parse(bytes)
            }
        } else null
        progress.checkCancelled()
        val resourceBySource = files.mapIndexedNotNull { index, file ->
            progress.checkCancelled()
            val source = installedEntryPrefix(index, file)
            ResourceTableResolver.scanApk(file, source)?.let { Triple(source, file, it) }
        }
        val resources = ResourceTableResolver.merge(resourceBySource.map { it.third })
        progress.emit(AnalysisStage.MANIFEST, 20, "Разрешаем resource references и Network Security Config…")
        val resolvedNetworkSecurity = ResourceTableResolver.resolveReference(resources, axmlOverlay?.networkSecurityConfigReference)
        val resolvedNetworkSecurityEntry = resolvedNetworkSecurity?.fileEntry
        val networkSecurityApk = resolvedNetworkSecurity?.sourceArchive?.let { source ->
            resourceBySource.firstOrNull { it.first == source }?.second
        } ?: base
        val networkSecurity = if (axmlOverlay?.networkSecurityConfigConfigured == true) {
            NetworkSecurityConfigScanner.scan(networkSecurityApk, axmlOverlay.networkSecurityConfigReference, resolvedNetworkSecurityEntry)
        } else null
        progress.checkCancelled()
        val manifest = if (baseStats?.hasAndroidManifest == true) inspectManifest(base, axmlOverlay, networkSecurity) else null
        require(manifest == null || manifest.packageName == app.packageName) {
            "Package name base APK не совпадает с выбранным установленным приложением"
        }
        progress.emit(AnalysisStage.MANIFEST, 24, "Manifest/resources готовы")

        val dexTotal = stats.sumOf { (it?.dexFiles ?: 0).coerceAtMost(MAX_DEX_FILES) }.coerceAtLeast(0)
        var dexBase = 0
        val dexParts = ArrayList<DexSummary>()
        progress.emit(AnalysisStage.DEX, 25, if (dexTotal > 0) "Начинаем DEX inventory и bytecode xrefs…" else "DEX не обнаружен", 0, dexTotal.takeIf { it > 0 })
        files.forEachIndexed { index, file ->
            val count = stats.getOrNull(index)?.dexFiles ?: 0
            if (count > 0) {
                progress.checkCancelled()
                dexParts += inspectDexStrings(
                    file, count, installedEntryPrefix(index, file), session, archiveIndexes.getOrNull(index),
                    progress = progress, overallBase = dexBase, overallTotal = dexTotal.coerceAtLeast(1),
                )
                dexBase += minOf(count, MAX_DEX_FILES)
            }
        }
        val dex = mergeDexSummaries(dexParts)
        progress.emit(AnalysisStage.DEX, 58, "DEX анализ завершён", dexBase.coerceAtMost(dexTotal), dexTotal.takeIf { it > 0 })

        progress.emit(AnalysisStage.REACHABILITY, 59, "Строим Manifest → DEX reachability…")
        val manifestDexReachability = ManifestDexReachabilityAnalyzer.analyze(manifest, dex)
        progress.checkCancelled()
        progress.emit(AnalysisStage.REACHABILITY, 61, "Reachability готова")

        val nativeTotal = stats.sumOf { (it?.nativeLibraries ?: 0).coerceAtMost(MAX_NATIVE_LIBRARIES) }.coerceAtLeast(0)
        var nativeBase = 0
        val nativeParts = ArrayList<NativeSummary>()
        progress.emit(AnalysisStage.NATIVE, 62, if (nativeTotal > 0) "Начинаем ELF/native inventory…" else "Native ELF библиотеки не обнаружены", 0, nativeTotal.takeIf { it > 0 })
        files.forEachIndexed { index, file ->
            val count = stats.getOrNull(index)?.nativeLibraries ?: 0
            if (count > 0) {
                progress.checkCancelled()
                nativeParts += inspectNativeLibraries(
                    file, count, installedEntryPrefix(index, file), session, archiveIndexes.getOrNull(index),
                    progress = progress, overallBase = nativeBase, overallTotal = nativeTotal.coerceAtLeast(1),
                )
                nativeBase += minOf(count, MAX_NATIVE_LIBRARIES)
            }
        }
        val nativeRaw = mergeNativeSummaries(nativeParts)
        val native = nativeRaw?.let { JniBridgeCorrelator.correlate(dex, it) }
        progress.emit(AnalysisStage.NATIVE, 76, "Native/JNI анализ завершён", nativeBase.coerceAtMost(nativeTotal), nativeTotal.takeIf { it > 0 })

        progress.emit(AnalysisStage.IL2CPP, 77, "Проверяем IL2CPP metadata и registration evidence…", 0, files.size)
        val il2cppParts = files.mapIndexedNotNull { index, file ->
            progress.checkCancelled()
            inspectIl2Cpp(file, native, archiveIndexes.getOrNull(index)).also {
                progress.scaled(AnalysisStage.IL2CPP, 77, 81, (index + 1).toLong(), files.size.toLong(), "IL2CPP: ${file.name}", index + 1, files.size)
            }
        }
        val il2cpp = chooseIl2Cpp(il2cppParts)

        progress.emit(AnalysisStage.RUNTIME, 82, "Определяем runtime-профили…")
        val runtimeEvidence = RuntimeProfileScanner.prepareSharedEvidence(dex, native)
        val runtimes = mergeRuntimeSummaries(files.mapIndexedNotNull { index, file ->
            progress.checkCancelled()
            RuntimeProfileScanner.scanApk(file, dex, native, il2cpp, sharedEvidence = runtimeEvidence, archiveIndex = archiveIndexes.getOrNull(index))
        })
        progress.emit(AnalysisStage.RUNTIME, 86, "Инвентаризируем Flutter/Hermes/Mono/Unreal artifacts…")
        val runtimeArtifacts = mergeRuntimeArtifacts(files.mapIndexedNotNull { index, file ->
            progress.checkCancelled()
            RuntimeArtifactScanner.scanApk(file, native, archiveIndex = archiveIndexes.getOrNull(index))
        })
        progress.emit(AnalysisStage.RUNTIME, 89, "Runtime анализ завершён")

        progress.emit(AnalysisStage.SUPPLY_CHAIN, 90, "Строим dependency inventory и SBOM evidence…", 0, files.size)
        val supplyChain = mergeSupplyChain(files.mapIndexed { index, file ->
            progress.checkCancelled()
            SupplyChainScanner.scan(file, dex, native, il2cpp, runtimeArtifacts, archiveIndex = archiveIndexes.getOrNull(index)).also {
                progress.scaled(AnalysisStage.SUPPLY_CHAIN, 90, 94, (index + 1).toLong(), files.size.toLong(), "Supply-chain: ${file.name}", index + 1, files.size)
            }
        })

        progress.emit(AnalysisStage.FINDINGS, 95, "Применяем статические security rules…")
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
        progress.emit(AnalysisStage.FINDINGS, 98, "Findings готовы: ${findings.size}")
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
        progress.emit(AnalysisStage.SAVING, 99, "Сохраняем результат в локальный SHA-256 кэш…")
        resultCache.store(report)
        progress.emit(AnalysisStage.COMPLETE, 100, "Анализ завершён")
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
        val fields = BoundedCollector<DexFieldReference>(MAX_REPORTED_DEX_FIELDS)
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
            fields.addAll(value.fields)
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
            classes.overflowed, methods.overflowed, fields.overflowed, nativeMethods.overflowed, codeMethods.overflowed,
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
            fieldsDeclared = values.sumOf { it.fieldsDeclared },
            fieldsIndexed = values.sumOf { it.fieldsIndexed },
            fields = fields.toList(),
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

    private fun chooseIl2Cpp(values: List<Il2CppSummary>): Il2CppSummary? = values.maxByOrNull { summary ->
        (if (summary.metadata?.magicValid == true) 1000 else 0) +
            (if (summary.detected) 100 else 0) + confidenceRank(summary.confidence) * 10 +
            summary.registrationCandidates.size.coerceAtMost(9)
    }

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
        progress: ProgressReporter = ProgressReporter(null),
    ): StaticAnalysisReport {
        val session = AnalysisSession()
        progress.emit(AnalysisStage.ARCHIVE, 10, "Индексируем ZIP central directory…")
        val archiveIndex = ApkArchiveIndex.build(apk)
        progress.checkCancelled()
        val archive = archiveOverride ?: archiveIndex?.let(::archiveStatsFromIndex) ?: inspectArchiveCentralDirectory(apk)
        progress.emit(
            AnalysisStage.ARCHIVE,
            14,
            "ZIP index готов: ${archive?.entries ?: 0} entries, ${archive?.dexFiles ?: 0} DEX, ${archive?.nativeLibraries ?: 0} native",
        )
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

        progress.emit(AnalysisStage.MANIFEST, 15, "Читаем AndroidManifest.xml и resource table…")
        val baseArchive = archive
        val axmlOverlay = if (baseArchive?.hasAndroidManifest == true) {
            val manifestBytes = readBoundedManifest(apk)
            manifestBytes?.let { bytes ->
                AxmlManifestOverlayParser.parse(NativeAnalysis.tryParseAxmlJson(bytes))
                    ?: KotlinAxmlManifestParser.parse(bytes)
            }
        } else null
        progress.checkCancelled()
        val resources = ResourceTableResolver.scanApk(apk, "artifact.apk")
        progress.emit(AnalysisStage.MANIFEST, 20, "Разрешаем resource references и Network Security Config…")
        val resolvedNetworkSecurityEntry = ResourceTableResolver.resolveReference(resources, axmlOverlay?.networkSecurityConfigReference)?.fileEntry
        val networkSecurity = if (axmlOverlay?.networkSecurityConfigConfigured == true) {
            NetworkSecurityConfigScanner.scan(apk, axmlOverlay.networkSecurityConfigReference, resolvedNetworkSecurityEntry)
        } else null
        progress.checkCancelled()
        val manifest = if (baseArchive?.hasAndroidManifest == true) inspectManifest(apk, axmlOverlay, networkSecurity) else null
        progress.emit(AnalysisStage.MANIFEST, 24, "Manifest/resources готовы")

        val dexCount = baseArchive?.dexFiles?.coerceAtMost(MAX_DEX_FILES) ?: 0
        progress.emit(AnalysisStage.DEX, 25, if (dexCount > 0) "Начинаем DEX inventory и bytecode xrefs…" else "DEX не обнаружен", 0, dexCount.takeIf { it > 0 })
        val dex = baseArchive?.dexFiles?.takeIf { it > 0 }?.let {
            inspectDexStrings(apk, it, session = session, archiveIndex = archiveIndex, progress = progress, overallBase = 0, overallTotal = dexCount.coerceAtLeast(1))
        }
        progress.emit(AnalysisStage.DEX, 58, "DEX анализ завершён", dex?.dexFilesScanned ?: 0, dexCount.takeIf { it > 0 })

        progress.emit(AnalysisStage.REACHABILITY, 59, "Строим Manifest → DEX reachability…")
        val manifestDexReachability = ManifestDexReachabilityAnalyzer.analyze(manifest, dex)
        progress.checkCancelled()
        progress.emit(AnalysisStage.REACHABILITY, 61, "Reachability готова")

        val nativeCount = baseArchive?.nativeLibraries?.coerceAtMost(MAX_NATIVE_LIBRARIES) ?: 0
        progress.emit(AnalysisStage.NATIVE, 62, if (nativeCount > 0) "Начинаем ELF/native inventory…" else "Native ELF библиотеки не обнаружены", 0, nativeCount.takeIf { it > 0 })
        val nativeRaw = baseArchive?.nativeLibraries?.takeIf { it > 0 }?.let {
            inspectNativeLibraries(apk, it, session = session, archiveIndex = archiveIndex, progress = progress, overallBase = 0, overallTotal = nativeCount.coerceAtLeast(1))
        }
        val native = nativeRaw?.let { JniBridgeCorrelator.correlate(dex, it) }
        progress.emit(AnalysisStage.NATIVE, 76, "Native/JNI анализ завершён", native?.librariesScanned ?: 0, nativeCount.takeIf { it > 0 })

        progress.emit(AnalysisStage.IL2CPP, 77, "Проверяем IL2CPP metadata и registration evidence…")
        val il2cpp = inspectIl2Cpp(apk, native, archiveIndex)
        progress.checkCancelled()
        progress.emit(AnalysisStage.IL2CPP, 81, "IL2CPP этап завершён")

        progress.emit(AnalysisStage.RUNTIME, 82, "Определяем runtime-профили…")
        val runtimeEvidence = RuntimeProfileScanner.prepareSharedEvidence(dex, native)
        val runtimes = RuntimeProfileScanner.scanApk(apk, dex, native, il2cpp, sharedEvidence = runtimeEvidence, archiveIndex = archiveIndex)
        progress.checkCancelled()
        progress.emit(AnalysisStage.RUNTIME, 86, "Инвентаризируем Flutter/Hermes/Mono/Unreal artifacts…")
        val runtimeArtifacts = RuntimeArtifactScanner.scanApk(apk, native, archiveIndex = archiveIndex)
        progress.checkCancelled()
        progress.emit(AnalysisStage.RUNTIME, 89, "Runtime анализ завершён")

        progress.emit(AnalysisStage.SUPPLY_CHAIN, 90, "Строим dependency inventory и SBOM evidence…")
        val supplyChain = SupplyChainScanner.scan(apk, dex, native, il2cpp, runtimeArtifacts, archiveIndex = archiveIndex)
        progress.checkCancelled()
        progress.emit(AnalysisStage.SUPPLY_CHAIN, 94, "Supply-chain/SBOM этап завершён")

        progress.emit(AnalysisStage.FINDINGS, 95, "Применяем статические security rules…")
        val findings = buildList {
            if (manifest != null) addAll(ManifestRuleEngine.evaluate(manifest))
            if (dex != null) addAll(DexRuleEngine.evaluate(dex))
            if (native != null) addAll(NativeRuleEngine.evaluate(native))
            if (il2cpp != null) addAll(Il2CppRuleEngine.evaluate(il2cpp))
        }.sortedWith(compareBy({ findingSeverityOrder(it.severity) }, { it.id }))
        progress.emit(AnalysisStage.FINDINGS, 98, "Findings готовы: ${findings.size}")
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
        // Discovery gates must use the complete central-directory counts. archive* counters are
        // intentionally bounded to the first ARCHIVE_STATS_LIMIT entries for summary statistics.
        dexFiles = index.dexEntryCount,
        nativeLibraries = index.nativeEntryCount,
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

    private fun aggregateInstalledHash(packageName: String, files: List<File>, progress: ProgressReporter? = null): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(packageName.toByteArray(Charsets.UTF_8))
        val totalBytes = files.sumOf { it.length().coerceAtLeast(0L) }.coerceAtLeast(1L)
        var completedBytes = 0L
        files.forEachIndexed { index, file ->
            checkCancelled()
            digest.update(index.toString().toByteArray(Charsets.UTF_8))
            digest.update(file.name.toByteArray(Charsets.UTF_8))
            file.inputStream().buffered(IO_BUFFER_BYTES).use { input ->
                val buffer = ByteArray(IO_BUFFER_BYTES)
                while (true) {
                    checkCancelled()
                    val read = input.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                    completedBytes += read
                    progress?.scaled(
                        AnalysisStage.HASHING, 1, 8, completedBytes, totalBytes,
                        "SHA-256: ${file.name} · ${formatBytes(completedBytes)} из ${formatBytes(totalBytes)}",
                        index + 1, files.size,
                    )
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
    private data class PreparedDexEntry(val reportedEntry: String, val file: File, val sha256: String, val ordinal: Int)
    private data class DexTaskResult(val prepared: PreparedDexEntry, val bundle: DexScanBundle?, val failed: Boolean)
    private data class DexCallKey(val entry: String, val caller: Int, val callee: Int, val offset: Int)
    private data class DexStringKey(val entry: String, val caller: Int, val stringIndex: Int, val offset: Int)
    private data class DexTypeKey(val entry: String, val caller: Int, val typeIndex: Int, val kind: String, val offset: Int)
    private data class DexFieldKey(val entry: String, val caller: Int, val fieldIndex: Int, val kind: String, val offset: Int)
    private data class DexBlockKey(val entry: String, val method: Int, val start: Int)
    private data class DexConstantKey(val entry: String, val method: Int, val register: Int, val offset: Int)
    private data class DexInvokeKey(val entry: String, val caller: Int, val callee: Int, val offset: Int)
    private data class PreparedNativeEntry(
        val reportedEntry: String,
        val rawEntryName: String,
        val bytes: Long,
        val file: File,
        val sha256: String,
        val ordinal: Int,
    )
    private data class NativeTaskResult(
        val prepared: PreparedNativeEntry,
        val library: NativeLibrarySummary?,
        val errorMessage: String? = null,
    )

    private fun rebaseDexInventory(value: DexStringScanner.FileResult, dexEntry: String): DexStringScanner.FileResult = value.copy(
        classes = value.classes.map { it.copy(dexEntry = dexEntry) },
        methods = value.methods.map { it.copy(dexEntry = dexEntry) },
        fields = value.fields.map { it.copy(dexEntry = dexEntry) },
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

    private fun obtainDexScan(
        reportedEntry: String,
        file: File,
        sha256: String,
        session: AnalysisSession,
        onProgress: ((percent: Int, detail: String, completed: Int?, total: Int?) -> Unit)? = null,
    ): DexScanBundle {
        checkCancelled()
        val existing = session.dexBySha256[sha256]
        if (existing != null) {
            onProgress?.invoke(100, "DEX content уже разобран в этой сессии; переиспользуем факты по SHA-256", null, null)
            return if (existing.sourceEntry == reportedEntry) existing else DexScanBundle(
                sourceEntry = reportedEntry,
                inventory = rebaseDexInventory(existing.inventory, reportedEntry),
                code = existing.code?.let { rebaseDexCode(it, reportedEntry) },
            )
        }

        val canonical = session.dexBySha256.computeIfAbsent(sha256) {
            checkCancelled()
            val inventory = DexStringScanner.scan(reportedEntry, file) { pct, detail, completed, total ->
                onProgress?.invoke((pct * 45) / 100, detail, completed, total)
            }
            checkCancelled()
            val code = try {
                DexCodeScanner.scan(
                    reportedEntry,
                    file,
                    structuralIndex = inventory.structuralIndex,
                ) { pct, detail, completed, total ->
                    onProgress?.invoke(45 + (pct * 55) / 100, detail, completed, total)
                }
            } catch (e: InterruptedIOException) {
                throw e
            } catch (_: Exception) {
                null
            }
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
        progress: ProgressReporter? = null,
        overallBase: Int = 0,
        overallTotal: Int = discovered.coerceAtLeast(1),
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
        var fieldsDeclared = 0L
        var fieldsIndexed = 0L
        var totalDexBytes = 0L
        val httpUrls = BoundedDistinctCollector<org.unirevlab.security.model.DexStringReference, Triple<String, Int, String>>(MAX_REPORTED_URLS) { Triple(it.dexEntry, it.stringIndex, it.value) }
        val httpsUrls = BoundedDistinctCollector<org.unirevlab.security.model.DexStringReference, Triple<String, Int, String>>(MAX_REPORTED_URLS) { Triple(it.dexEntry, it.stringIndex, it.value) }
        val secretCandidates = BoundedDistinctCollector<org.unirevlab.security.model.SecretCandidate, Triple<String, String, Int>>(MAX_REPORTED_SECRET_CANDIDATES) { Triple(it.kind, it.dexEntry, it.stringIndex) }
        val classes = BoundedDistinctCollector<DexClassReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_CLASSES) { Triple(it.dexEntry, it.classIndex, it.descriptor) }
        val methods = BoundedDistinctCollector<DexMethodReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_METHODS) { Triple(it.dexEntry, it.methodIndex, it.declaringClass) }
        val fields = BoundedDistinctCollector<DexFieldReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_FIELDS) { Triple(it.dexEntry, it.fieldIndex, it.declaringClass) }
        val nativeMethods = BoundedDistinctCollector<DexNativeMethodDeclaration, Triple<String, Int, String>>(MAX_REPORTED_NATIVE_METHODS) { Triple(it.dexEntry, it.methodIndex, it.declaringClass) }
        val codeMethods = BoundedDistinctCollector<DexMethodCodeReference, Triple<String, Int, Long>>(MAX_REPORTED_CODE_METHODS) { Triple(it.dexEntry, it.methodIndex, it.codeOffset) }
        val callXrefs = BoundedDistinctCollector<DexMethodCallXref, DexCallKey>(MAX_REPORTED_CALL_XREFS) { DexCallKey(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }
        val stringXrefs = BoundedDistinctCollector<DexStringXref, DexStringKey>(MAX_REPORTED_STRING_XREFS) { DexStringKey(it.dexEntry, it.callerMethodIndex, it.stringIndex, it.instructionOffsetCodeUnits) }
        val typeXrefs = BoundedDistinctCollector<DexTypeXref, DexTypeKey>(MAX_REPORTED_TYPE_XREFS) { DexTypeKey(it.dexEntry, it.callerMethodIndex, it.typeIndex, it.kind, it.instructionOffsetCodeUnits) }
        val fieldXrefs = BoundedDistinctCollector<DexFieldXref, DexFieldKey>(MAX_REPORTED_FIELD_XREFS) { DexFieldKey(it.dexEntry, it.callerMethodIndex, it.fieldIndex, it.kind, it.instructionOffsetCodeUnits) }
        val basicBlocks = BoundedDistinctCollector<DexBasicBlock, DexBlockKey>(MAX_REPORTED_BASIC_BLOCKS) { DexBlockKey(it.dexEntry, it.methodIndex, it.startCodeUnit) }
        val constants = BoundedDistinctCollector<DexConstantReference, DexConstantKey>(MAX_REPORTED_CONSTANTS) { DexConstantKey(it.dexEntry, it.methodIndex, it.register, it.instructionOffsetCodeUnits) }
        val invokeObservations = BoundedDistinctCollector<DexInvokeObservation, DexInvokeKey>(MAX_REPORTED_INVOKE_OBSERVATIONS) { DexInvokeKey(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }

        val dexProgressFractions = DoubleArray(overallTotal.coerceAtLeast(1)) { index -> if (index < overallBase) 1.0 else 0.0 }
        val dexProgressLock = Any()
        fun updateDexProgress(ordinal: Int, localFraction: Double): Pair<Double, Int> = synchronized(dexProgressLock) {
            val slot = (ordinal - 1).coerceIn(0, dexProgressFractions.lastIndex)
            dexProgressFractions[slot] = maxOf(dexProgressFractions[slot], localFraction.coerceIn(0.0, 1.0))
            val overallFraction = dexProgressFractions.sum() / dexProgressFractions.size.toDouble()
            val completed = dexProgressFractions.count { it >= 0.999999 }
            overallFraction to completed
        }

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
                                prepared += PreparedDexEntry(reportedEntry, tempDex, copied.sha256, overallBase + cursor)
                            } catch (e: InterruptedIOException) {
                                tempDex.delete()
                                throw e
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
                                    val bundle = obtainDexScan(item.reportedEntry, item.file, item.sha256, session) { localPercent, detail, completed, total ->
                                        val (globalFraction, completedDex) = updateDexProgress(
                                            item.ordinal, localPercent.coerceIn(0, 100) / 100.0,
                                        )
                                        val precisePercent = 25.0 + globalFraction.coerceIn(0.0, 1.0) * 33.0
                                        progress?.emit(
                                            AnalysisStage.DEX,
                                            precisePercent.toInt(),
                                            "${item.reportedEntry}: $detail",
                                            completedDex,
                                            overallTotal,
                                            fractionComplete = precisePercent / 100.0,
                                        )
                                    }
                                    DexTaskResult(item, bundle, failed = false)
                                } catch (e: InterruptedIOException) {
                                    throw e
                                } catch (_: Exception) {
                                    DexTaskResult(item, bundle = null, failed = true)
                                }
                            })
                        }
                        try {
                            for (future in futures) {
                                val task = try {
                                    future.get()
                                } catch (e: InterruptedException) {
                                    futures.forEach { it.cancel(true) }
                                    Thread.currentThread().interrupt()
                                    throw InterruptedIOException("DEX analysis cancelled")
                                } catch (e: FutureCancellationException) {
                                    throw InterruptedIOException("DEX analysis cancelled")
                                } catch (e: ExecutionException) {
                                    val cause = e.cause
                                    if (cause is InterruptedIOException || cause is InterruptedException) {
                                        futures.forEach { it.cancel(true) }
                                        throw InterruptedIOException("DEX analysis cancelled")
                                    }
                                    throw e
                                }
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
                                fieldsDeclared += scan.fieldsDeclared.toLong()
                                fieldsIndexed += scan.fieldsIndexed.toLong()
                                classes.addAll(scan.classes)
                                methods.addAll(scan.methods)
                                fields.addAll(scan.fields)
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
                                val (globalFraction, completedDex) = updateDexProgress(task.prepared.ordinal, 1.0)
                                val precisePercent = 25.0 + globalFraction.coerceIn(0.0, 1.0) * 33.0
                                progress?.emit(
                                    AnalysisStage.DEX,
                                    precisePercent.toInt(),
                                    "DEX готов: ${task.prepared.reportedEntry}",
                                    completedDex,
                                    overallTotal,
                                    fractionComplete = precisePercent / 100.0,
                                )
                            }
                        } finally {
                            if (Thread.currentThread().isInterrupted) futures.forEach { it.cancel(true) }
                            prepared.forEach { it.file.delete() }
                        }
                    }
                }
            }
        } catch (e: InterruptedIOException) {
            throw e
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
            fieldsDeclared = fieldsDeclared,
            fieldsIndexed = fieldsIndexed,
            fields = fields.toList(),
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
                classes.overflowed, methods.overflowed, fields.overflowed, nativeMethods.overflowed, codeMethods.overflowed,
                callXrefs.overflowed, stringXrefs.overflowed, typeXrefs.overflowed, fieldXrefs.overflowed,
                basicBlocks.overflowed, constants.overflowed, invokeObservations.overflowed,
                httpUrls.overflowed, httpsUrls.overflowed, secretCandidates.overflowed,
            ).any { it },
        )
    }

    private fun inspectIl2Cpp(apk: File, native: NativeSummary?, archiveIndex: ApkArchiveIndex? = null): Il2CppSummary? =
        Il2CppScanner.scanApk(
            apk, native,
            archiveEntryNames = archiveIndex?.runtimeArtifactEntries?.asSequence()?.map { it.name }?.toList(),
        )

    private fun inspectNativeLibraries(
        apk: File,
        discovered: Int,
        entryPrefix: String? = null,
        session: AnalysisSession = AnalysisSession(),
        archiveIndex: ApkArchiveIndex? = null,
        progress: ProgressReporter? = null,
        overallBase: Int = 0,
        overallTotal: Int = discovered.coerceAtLeast(1),
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
                                prepared += PreparedNativeEntry(reportedEntry, entry.name, copied.bytes, tempElf, copied.sha256, overallBase + cursor)
                            }
                        } catch (e: InterruptedIOException) {
                            tempElf.delete()
                            throw e
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
                                checkCancelled()
                                val cached = session.nativeBySha256[item.sha256]
                                val canonical = if (cached != null) {
                                    progress?.emit(
                                        AnalysisStage.NATIVE,
                                        62 + (((item.ordinal.toDouble() / overallTotal.coerceAtLeast(1).toDouble()).coerceIn(0.0, 1.0)) * 14.0).toInt(),
                                        "${item.reportedEntry}: native content уже разобран; переиспользуем SHA-256 факты",
                                        (item.ordinal - 1).coerceAtLeast(0).coerceAtMost(overallTotal),
                                        overallTotal,
                                    )
                                    cached
                                } else {
                                    session.nativeBySha256.computeIfAbsent(item.sha256) {
                                        ElfNativeScanner.scan(item.reportedEntry, item.file) { localPercent, detail, completed, total ->
                                            val completedBefore = (item.ordinal - 1).coerceAtLeast(0)
                                            val globalFraction = (completedBefore.toDouble() + localPercent.coerceIn(0, 100) / 100.0) / overallTotal.coerceAtLeast(1).toDouble()
                                            val globalPercent = 62 + (globalFraction.coerceIn(0.0, 1.0) * 14.0).toInt()
                                            progress?.emit(
                                                AnalysisStage.NATIVE, globalPercent, "${item.reportedEntry}: $detail",
                                                completedBefore.coerceAtMost(overallTotal), overallTotal,
                                            )
                                        }
                                    }
                                }
                                NativeTaskResult(item, rebaseNativeLibrary(canonical, item.reportedEntry))
                            } catch (e: InterruptedIOException) {
                                throw e
                            } catch (e: Exception) {
                                NativeTaskResult(item, null, e.message ?: e::class.java.simpleName)
                            }
                        })
                    }
                    try {
                        for (future in futures) {
                            val task = try {
                                future.get()
                            } catch (e: InterruptedException) {
                                futures.forEach { it.cancel(true) }
                                Thread.currentThread().interrupt()
                                throw InterruptedIOException("Native analysis cancelled")
                            } catch (e: FutureCancellationException) {
                                throw InterruptedIOException("Native analysis cancelled")
                            } catch (e: ExecutionException) {
                                val cause = e.cause
                                if (cause is InterruptedIOException || cause is InterruptedException) {
                                    futures.forEach { it.cancel(true) }
                                    throw InterruptedIOException("Native analysis cancelled")
                                }
                                throw e
                            }
                            val scan = task.library
                            if (scan != null) {
                                filesScanned++
                                libraries += scan
                                if (scan.truncated) truncated = true
                            } else {
                                parseErrors++
                                libraries += failureLibrary(task.prepared, task.errorMessage ?: "native parse failed")
                            }
                            progress?.emit(
                                AnalysisStage.NATIVE,
                                62 + (((task.prepared.ordinal.toDouble() / overallTotal.coerceAtLeast(1).toDouble()).coerceIn(0.0, 1.0)) * 14.0).toInt(),
                                "Native готов: ${task.prepared.reportedEntry}",
                                task.prepared.ordinal.coerceAtMost(overallTotal),
                                overallTotal,
                            )
                        }
                    } finally {
                        if (Thread.currentThread().isInterrupted) futures.forEach { it.cancel(true) }
                        prepared.forEach { it.file.delete() }
                    }
                }
            }
        } catch (e: InterruptedIOException) {
            throw e
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

    private fun copyToBoundedTempAndHash(
        uri: Uri,
        destination: File,
        expectedBytes: Long? = null,
        onBytes: ((copied: Long, total: Long?) -> Unit)? = null,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Не удалось открыть выбранный файл" }
            FileOutputStream(destination).use { fileOutput ->
                DigestOutputStream(fileOutput, digest).use { output ->
                    val buffer = ByteArray(IO_BUFFER_BYTES)
                    var total = 0L
                    while (true) {
                        checkCancelled()
                        val read = input.read(buffer)
                        if (read <= 0) break
                        total += read
                        require(total <= MAX_ARTIFACT_BYTES) {
                            "Артефакт превышает локальный лимит ${MAX_ARTIFACT_BYTES / (1024 * 1024)} MiB"
                        }
                        output.write(buffer, 0, read)
                        onBytes?.invoke(total, expectedBytes)
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
                    checkCancelled()
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
                        checkCancelled()
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

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1024L * 1024L * 1024L -> "%.1f GiB".format(bytes.toDouble() / (1024.0 * 1024.0 * 1024.0))
        bytes >= 1024L * 1024L -> "%.1f MiB".format(bytes.toDouble() / (1024.0 * 1024.0))
        bytes >= 1024L -> "%.1f KiB".format(bytes.toDouble() / 1024.0)
        else -> "$bytes B"
    }

    private data class ArchiveStats(
        val entries: Int,
        val dexFiles: Int,
        val nativeLibraries: Int,
        val hasAndroidManifest: Boolean,
        val suspiciousPaths: Int,
        val truncated: Boolean,
    )

    companion object {
        const val ENGINE_VERSION = "0.25.8-dev-apkset-sources"

        private fun checkCancelled() {
            if (Thread.currentThread().isInterrupted) throw InterruptedIOException("Analysis cancelled")
        }
        private const val MAX_DEX_FILES = 32
        private const val MAX_SINGLE_DEX_BYTES = 96L * 1024L * 1024L
        private const val MAX_TOTAL_DEX_BYTES = 384L * 1024L * 1024L
        private const val MAX_REPORTED_URLS = 500
        private const val MAX_REPORTED_SECRET_CANDIDATES = 200
        private const val MAX_REPORTED_DEX_CLASSES = 8_000
        private const val MAX_REPORTED_DEX_METHODS = 16_000
        private const val MAX_REPORTED_DEX_FIELDS = 48_000
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
                Thread({
                    runCatching { android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_MORE_FAVORABLE) }
                    runnable.run()
                }, "unirevlab-analysis").apply { isDaemon = true }
            }
    }
}
