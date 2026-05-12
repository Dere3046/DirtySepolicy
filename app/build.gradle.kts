plugins {
    id("com.android.application")
}

android {
    enableKotlin = false
    namespace = "org.lsposed.dirtysepolicy"
    defaultConfig {
        versionCode = 2
        versionName = "1.1"
    }
    buildTypes {
        release {
            vcsInfo.include = false
            signingConfig = signingConfigs["debug"]
            optimization {
                enable = true
                keepRules {
                    ignoreFromAllExternalDependencies = true
                    includeDefault = false
                }
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures {
        aidl = true
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
    defaultConfig {
        externalNativeBuild {
            cmake {
                cppFlags += "-O3 -fvisibility=hidden -fvisibility-inlines-hidden"
                arguments += "-DANDROID_STL=c++_static"
            }
        }
    }
    packaging {
        resources {
            excludes += "**"
        }
    }
    lint {
        checkReleaseBuilds = false
    }
    dependenciesInfo {
        includeInApk = false
    }
}

dependencies {
    compileOnly(projects.stub)
}
