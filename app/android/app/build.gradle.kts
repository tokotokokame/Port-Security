plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.tokotokokame.port_security"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.tokotokokame.port_security"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        // CI decodes the keystore from repository secrets; never commit key material.
        val keystore = System.getenv("ANDROID_KEYSTORE_PATH")
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // 正式リリース（CI の main）は正式な署名鍵が必須。REQUIRE_RELEASE_SIGNING=1 で鍵がなければ失敗する。
            // それ以外（ローカル・PR の検証）はデバッグ鍵で署名する。デバッグ鍵の APK は公開しない。
            val release = signingConfigs.findByName("release")
            if (release == null && System.getenv("REQUIRE_RELEASE_SIGNING") == "1") {
                throw GradleException("REQUIRE_RELEASE_SIGNING=1 but ANDROID_KEYSTORE_PATH is not set")
            }
            signingConfig = release ?: signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}
