#include <jni.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <android/log.h>

#define LOG_TAG "DirtySepolicyNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

// Native write attr probe (bypasses Java layer hooks)
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeWriteAttrProbe(JNIEnv *env, jclass clazz, jstring contextStr) {
    const char *context = env->GetStringUTFChars(contextStr, nullptr);
    std::string result;
    
    int fd = open("/proc/self/attr/current", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        result = "ERROR: open failed errno=" + std::to_string(errno);
        env->ReleaseStringUTFChars(contextStr, context);
        return env->NewStringUTF(result.c_str());
    }
    
    ssize_t written = write(fd, context, strlen(context));
    int err = errno;
    close(fd);
    
    if (written >= 0) {
        result = "SUCCESS: write succeeded";
    } else if (err == EINVAL) {
        result = "NORMAL_EINVAL: errno=" + std::to_string(err);
    } else {
        result = "DETECTED_NON_EINVAL: errno=" + std::to_string(err);
    }
    
    env->ReleaseStringUTFChars(contextStr, context);
    return env->NewStringUTF(result.c_str());
}

// Check if a mount entry contains magisk-related strings
static bool isMagiskMount(const std::string& line) {
    return line.find("magisk") != std::string::npos ||
           line.find(".magisk") != std::string::npos ||
           line.find("/debug_ramdisk") != std::string::npos ||
           line.find("/sbin") != std::string::npos;
}

// Scan /proc/self/mountinfo for magisk mounts
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanMounts(JNIEnv *env, jclass clazz) {
    std::string result;
    std::ifstream mounts("/proc/self/mountinfo");
    std::string line;
    int count = 0;
    
    while (std::getline(mounts, line)) {
        if (isMagiskMount(line)) {
            if (count < 5) {
                result += line + "\n";
            }
            count++;
        }
    }
    
    if (count > 0) {
        result = "DETECTED: " + std::to_string(count) + " suspicious mounts\n" + result;
    } else {
        result = "CLEAN: no suspicious mounts";
    }
    
    return env->NewStringUTF(result.c_str());
}

// Scan for magisk-related environment variables
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanEnv(JNIEnv *env, jclass clazz) {
    std::string result;
    extern char **environ;
    int count = 0;
    
    for (char **env = environ; *env != nullptr; env++) {
        std::string entry(*env);
        if (entry.find("MAGISK") != std::string::npos ||
            entry.find("magisk") != std::string::npos ||
            entry.find("KSU") != std::string::npos ||
            entry.find("kernelsu") != std::string::npos) {
            if (count < 10) {
                result += entry + "\n";
            }
            count++;
        }
    }
    
    if (count > 0) {
        result = "DETECTED: " + std::to_string(count) + " suspicious env vars\n" + result;
    } else {
        result = "CLEAN: no suspicious env vars";
    }
    
    return env->NewStringUTF(result.c_str());
}

// Check for magisk-related files in common paths
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanFiles(JNIEnv *env, jclass clazz) {
    std::string result;
    int count = 0;
    
    const char* checkPaths[] = {
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/modules",
        "/sbin/.magisk",
        "/debug_ramdisk/.magisk",
        nullptr
    };
    
    for (int i = 0; checkPaths[i] != nullptr; i++) {
        struct stat st;
        if (stat(checkPaths[i], &st) == 0) {
            result += std::string(checkPaths[i]) + " exists\n";
            count++;
        }
    }
    
    if (count > 0) {
        result = "DETECTED: " + std::to_string(count) + " suspicious files/dirs\n" + result;
    } else {
        result = "CLEAN: no suspicious files/dirs";
    }
    
    return env->NewStringUTF(result.c_str());
}

// Randomized domain detection: try to find unknown custom domains
// by checking if write to a randomized pattern succeeds
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeRandomizedDomainProbe(JNIEnv *env, jclass clazz) {
    std::string result;
    
    // Try common randomized patterns
    const char* testDomains[] = {
        "u:r:magisk:s0",           // fallback
        "u:r:abc123:s0",           // example random
        nullptr
    };
    
    // Actually, we can't guess random names. Instead, check for side effects:
    // - Check if there are any domains we can transition to that shouldn't exist
    // - Check for execmem (already done in Java)
    
    result = "INFO: randomized domain detection relies on side-channel analysis\n";
    result += "Use execmem, mount, and file checks for indirect detection";
    
    return env->NewStringUTF(result.c_str());
}

// Comprehensive native detection
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeFullScan(JNIEnv *env, jclass clazz) {
    std::string result = "=== Native Detection Report ===\n";
    
    // 1. Write attr probes
    result += "\n[Write Attr Probes]\n";
    const char* contexts[] = {
        "u:r:ksu:s0",
        "u:object_r:ksu_file:s0",
        "u:r:magisk:s0",
        "u:object_r:magisk_file:s0",
        "u:r:lsposed_file:s0",
        "u:r:xposed_data:s0",
        nullptr
    };
    
    for (int i = 0; contexts[i] != nullptr; i++) {
        jstring ctx = env->NewStringUTF(contexts[i]);
        jstring probeResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeWriteAttrProbe(env, clazz, ctx);
        const char* probeStr = env->GetStringUTFChars(probeResult, nullptr);
        result += std::string(contexts[i]) + " -> " + probeStr + "\n";
        env->ReleaseStringUTFChars(probeResult, probeStr);
        env->DeleteLocalRef(ctx);
        env->DeleteLocalRef(probeResult);
    }
    
    // 2. Mount scan
    result += "\n[Mount Scan]\n";
    jstring mountResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanMounts(env, clazz);
    const char* mountStr = env->GetStringUTFChars(mountResult, nullptr);
    result += mountStr;
    result += "\n";
    env->ReleaseStringUTFChars(mountResult, mountStr);
    env->DeleteLocalRef(mountResult);
    
    // 3. Env scan
    result += "\n[Environment Scan]\n";
    jstring envResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanEnv(env, clazz);
    const char* envStr = env->GetStringUTFChars(envResult, nullptr);
    result += envStr;
    result += "\n";
    env->ReleaseStringUTFChars(envResult, envStr);
    env->DeleteLocalRef(envResult);
    
    // 4. File scan
    result += "\n[File Scan]\n";
    jstring fileResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanFiles(env, clazz);
    const char* fileStr = env->GetStringUTFChars(fileResult, nullptr);
    result += fileStr;
    result += "\n";
    env->ReleaseStringUTFChars(fileResult, fileStr);
    env->DeleteLocalRef(fileResult);
    
    result += "\n=== End Native Report ===";
    return env->NewStringUTF(result.c_str());
}

} // extern "C"