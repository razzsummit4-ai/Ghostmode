import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("org.jetbrains.kotlin.android")
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing credentials, kept out of version control.
//
// The keystore is what identifies the app to Android: an update signed with a
// different key is refused, so this file and the .jks beside it must be
// preserved together. When absent, the build falls back to the debug key so a
// fresh clone still compiles and produces an installable artifact.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}
val hasReleaseKeystore = keystoreProperties.getProperty("storeFile") != null

android {
    namespace = "com.securechat.securechat"
    // Pinned rather than inherited from the Flutter template. Several plugins
    // (permission_handler, flutter_reactive_ble) declare compileSdk 37, and
    // Gradle fails the build if this module compiles against anything lower.
    compileSdk = 37
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.securechat.securechat"
        // 24 is Android 7.0, and it is a floor rather than a preference.
        //
        // flutter_secure_storage v11 - which is where this app's private keys
        // live - sets minSdk 24 itself, because below API 24 the Android
        // Keystore cannot back the encrypted preferences it depends on.
        // Gradle fails the build if this module asks for less, and forcing it
        // lower would mean downgrading the component that protects every
        // identity key on the device. Older plugins (v9) allowed API 19, but
        // that path should not be taken for key storage.
        //
        // Consequence: a handset below Android 7.0 cannot install this app at
        // all, and the installer only says "app not installed". The landing page
        // states the requirement so that is visible before anyone tries.
        //
        // This is unrelated to CPU architecture: a 32-bit phone on Android 7 or
        // newer installs fine, it just needs the armeabi-v7a build.
        minSdk = 24
        targetSdk = 37
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = if (hasReleaseKeystore) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }

            // Keep the release build small and free of unneeded dev tooling.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    // A universal APK carries all three ABIs, so it runs on any handset. The
    // per-ABI splits are emitted alongside it so a user on a slow connection can
    // download only what their own device needs.
    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }
}


kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
