plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.unirevlab.security"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.unirevlab.security"
        minSdk = 26
        targetSdk = 36
        versionCode = 19
        versionName = "0.22.1-dev-analysis-progress-cancel"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        val store = System.getenv("UNIREVLAB_RELEASE_STORE_FILE")
        val storePassword = System.getenv("UNIREVLAB_RELEASE_STORE_PASSWORD")
        val keyAliasValue = System.getenv("UNIREVLAB_RELEASE_KEY_ALIAS")
        val keyPasswordValue = System.getenv("UNIREVLAB_RELEASE_KEY_PASSWORD")
        if (!store.isNullOrBlank() && !storePassword.isNullOrBlank() && !keyAliasValue.isNullOrBlank() && !keyPasswordValue.isNullOrBlank()) {
            create("release") {
                storeFile = file(store)
                this.storePassword = storePassword
                keyAlias = keyAliasValue
                keyPassword = keyPasswordValue
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.08.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")

    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}


tasks.register("verifyReleaseSigningInputs") {
    doLast {
        val required = listOf(
            "UNIREVLAB_RELEASE_STORE_FILE",
            "UNIREVLAB_RELEASE_STORE_PASSWORD",
            "UNIREVLAB_RELEASE_KEY_ALIAS",
            "UNIREVLAB_RELEASE_KEY_PASSWORD",
        )
        val missing = required.filter { System.getenv(it).isNullOrBlank() }
        require(missing.isEmpty()) { "Missing release signing environment: ${missing.joinToString()}" }
        val store = file(System.getenv("UNIREVLAB_RELEASE_STORE_FILE"))
        require(store.isFile) { "Release keystore file does not exist: $store" }
    }
}
