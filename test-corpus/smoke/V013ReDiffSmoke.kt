import org.unirevlab.security.analysis.AssessmentDiffEngine
import org.unirevlab.security.analysis.ReBrowserIndex
import org.unirevlab.security.model.*

fun main() {
    val dex = DexSummary(
        dexFilesDiscovered=1,dexFilesScanned=1,stringsDeclared=2,stringsScanned=2,typesDeclared=2,typesIndexed=2,classesDeclared=1,classesIndexed=1,methodsDeclared=2,methodsIndexed=2,
        classes=listOf(DexClassReference("classes.dex",0,"Lcom/example/Main;","Ljava/lang/Object;",1)),
        methods=listOf(
            DexMethodReference("classes.dex",0,"Lcom/example/Main;","start","()V"),
            DexMethodReference("classes.dex",1,"Lcom/example/Main;","sink","(Ljava/lang/String;)V")
        ),
        callXrefs=listOf(DexMethodCallXref("classes.dex",0,"Lcom/example/Main;","start",1,"Lcom/example/Main;","sink","(Ljava/lang/String;)V",4)),
        stringXrefs=listOf(DexStringXref("classes.dex",0,"Lcom/example/Main;","start",0,"https://example.test/api",2)),
        fieldXrefs=listOf(DexFieldXref("classes.dex",0,"Lcom/example/Main;","start",0,"Lcom/example/Main;","token","Ljava/lang/String;","SGET",1)),
        basicBlocks=listOf(DexBasicBlock("classes.dex",0,0,0,6,listOf(),"RETURN")),
        httpUrls=emptyList(),httpsUrls=emptyList(),secretCandidates=emptyList(),parseErrors=0,truncated=false
    )
    val index = ReBrowserIndex.buildDex(dex)
    check(index.packages.single().name == "com.example")
    val start = index.packages.single().classes.single().methods.first { it.name == "start" }
    check(start.callees.single().contains("sink"))
    check(start.strings.single().contains("example.test"))
    check(start.fields.single().contains("token"))
    check(start.basicBlockCount == 1)
    check(ReBrowserIndex.searchDex(index,"sink").isNotEmpty())

    val before = report("1.0", listOf("android.permission.INTERNET"), emptyList(), listOf("aa"), "4.11.0")
    val after = report("2.0", listOf("android.permission.INTERNET","android.permission.CAMERA"), listOf(ComponentExposure("activity",".DebugActivity",true)), listOf("bb"), "4.12.0")
    val diff = AssessmentDiffEngine.diff(before, after)
    check(diff.signerChanged)
    check(diff.items.any { it.category == "permission" && it.key == "android.permission.CAMERA" && it.change == "ADDED" })
    check(diff.items.any { it.category == "exportedComponent" && it.change == "ADDED" })
    check(diff.items.any { it.category == "dependency" && it.change == "ADDED" && it.key.contains("4.12.0") })
    check(diff.items.any { it.category == "signing" && it.change == "CHANGED" })
    println("v0.13 RE index + assessment diff smoke: PASS")
}

private fun report(version:String, permissions:List<String>, components:List<ComponentExposure>, signers:List<String>, depVersion:String): StaticAnalysisReport {
    return StaticAnalysisReport(
        engineVersion="0.13-dev",
        assessment=AssessmentScope(projectName="p",organization="o",purpose="authorized test",confirmsAuthority=true),
        artifact=ArtifactSummary("app.apk",1,"0".repeat(64),1,1,0,true,0,false),
        manifest=ManifestSummary(
            packageName="com.example",versionName=version,versionCode=if(version=="1.0")1 else 2,minSdk=26,targetSdk=36,debuggable=false,allowBackup=false,
            fullBackupContentConfigured=null,dataExtractionRulesConfigured=null,usesCleartextTraffic=false,networkSecurityConfigConfigured=null,
            requestedPermissions=permissions,dangerousPermissions=permissions.filter { it.endsWith("CAMERA") },components=components,signingCertificateSha256=signers
        ),
        supplyChain=SupplyChainSummary(
            components=listOf(DependencyComponentSummary("pkg:maven/com.squareup.okhttp3/okhttp", "okhttp", "maven", depVersion, "pkg:maven/com.squareup.okhttp3/okhttp@$depVersion", "HIGH", listOf("pom.properties"), "pom.properties")),
            nativeDependencies=emptyList(),truncated=false
        ),
        findings=emptyList()
    )
}
