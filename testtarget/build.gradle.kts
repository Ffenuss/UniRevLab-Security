plugins {
    id("com.android.application")
}

android {
    namespace = "org.unirevlab.testtarget"
    compileSdk {
        version = release(37) {
            minorApiLevel = 0
        }
    }
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.unirevlab.testtarget"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0-regression-fixture"

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c11"
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
