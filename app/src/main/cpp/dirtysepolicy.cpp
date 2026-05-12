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
#include <linux/limits.h>

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

// Native write attr probe with custom path (for procattr bypass)
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeWriteAttrProbePath(JNIEnv *env, jclass clazz, jstring pathStr, jstring contextStr) {
    const char *path = env->GetStringUTFChars(pathStr, nullptr);
    const char *context = env->GetStringUTFChars(contextStr, nullptr);
    std::string result;
    
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        result = "ERROR: open failed errno=" + std::to_string(errno);
        env->ReleaseStringUTFChars(pathStr, path);
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
    
    env->ReleaseStringUTFChars(pathStr, path);
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

// Scan SELinux policy binary for known signatures
// This bypasses KSU PR#3459 completely because it reads policy directly
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanPolicy(JNIEnv *env, jclass clazz) {
    std::string result;
    
    int fd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        result = "ERROR: cannot open policy errno=" + std::to_string(errno);
        return env->NewStringUTF(result.c_str());
    }
    
    // Read policy in chunks and search for strings
    const size_t BUF_SIZE = 4096;
    char buf[BUF_SIZE];
    ssize_t n;
    
    // Known signatures to search for
    const char* signatures[] = {
        "ksu",              // KernelSU domain/type
        "magisk",           // Magisk domain/type (fallback)
        "lsposed",          // LSPosed
        "xposed",           // Xposed
        "adbroot",          // adb_root
        nullptr
    };
    
    // For randomized domains: look for suspicious patterns
    // - 10-char lowercase+numeric strings that are domains
    // This is heuristic and may have false positives
    int sigCount = 0;
    std::string sigFound;
    
    while ((n = read(fd, buf, BUF_SIZE)) > 0) {
        for (int s = 0; signatures[s] != nullptr; s++) {
            const char* sig = signatures[s];
            size_t sigLen = strlen(sig);
            for (ssize_t i = 0; i <= n - (ssize_t)sigLen; i++) {
                if (memcmp(buf + i, sig, sigLen) == 0) {
                    sigCount++;
                    if (sigFound.length() < 200) {
                        sigFound += std::string(sig) + " ";
                    }
                }
            }
        }
    }
    
    close(fd);
    
    if (sigCount > 0) {
        result = "DETECTED: " + std::to_string(sigCount) + " signature matches: " + sigFound;
    } else {
        result = "CLEAN: no known signatures in policy";
    }
    
    return env->NewStringUTF(result.c_str());
}

// Scan /proc for magiskd/zygiskd processes
// Even if domain name is randomized, process name and cmdline remain
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanProcesses(JNIEnv *env, jclass clazz) {
    std::string result;
    int count = 0;
    
    DIR* proc = opendir("/proc");
    if (!proc) {
        result = "ERROR: cannot open /proc";
        return env->NewStringUTF(result.c_str());
    }
    
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        
        // Check if it's a PID directory
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') continue;  // not a number
        
        // Read /proc/<pid>/cmdline
        char cmdlinePath[256];
        snprintf(cmdlinePath, sizeof(cmdlinePath), "/proc/%s/cmdline", entry->d_name);
        
        int fd = open(cmdlinePath, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        
        char cmdline[256];
        ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        
        if (n <= 0) continue;
        cmdline[n] = '\0';
        
        // Check for magisk-related process names
        if (strstr(cmdline, "magiskd") ||
            strstr(cmdline, "magisk") ||
            strstr(cmdline, "zygiskd") ||
            strstr(cmdline, "ksud") ||
            strstr(cmdline, "ksu")) {
            
            // Read SELinux context
            char contextPath[256];
            snprintf(contextPath, sizeof(contextPath), "/proc/%s/attr/current", entry->d_name);
            
            char context[256] = "unknown";
            int ctxFd = open(contextPath, O_RDONLY | O_CLOEXEC);
            if (ctxFd >= 0) {
                ssize_t ctxN = read(ctxFd, context, sizeof(context) - 1);
                if (ctxN > 0) {
                    context[ctxN] = '\0';
                    // Trim newline
                    char* nl = strchr(context, '\n');
                    if (nl) *nl = '\0';
                }
                close(ctxFd);
            }
            
            if (count < 5) {
                result += std::string("PID ") + entry->d_name + ": " + cmdline + " [" + context + "]\n";
            }
            count++;
        }
    }
    
    closedir(proc);
    
    if (count > 0) {
        result = "DETECTED: " + std::to_string(count) + " suspicious processes\n" + result;
    } else {
        result = "CLEAN: no suspicious processes";
    }
    
    return env->NewStringUTF(result.c_str());
}

// Comprehensive native detection
JNIEXPORT jstring JNICALL
Java_org_lsposed_dirtysepolicy_AppZygote_nativeFullScan(JNIEnv *env, jclass clazz) {
    std::string result = "=== Native Detection Report ===\n";
    
    // 1. Write attr probes
    result += "\n[Write Attr Probes (current)]\n";
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
    
    // 2. Procattr bypass probes
    result += "\n[Procattr Bypass Probes]\n";
    const char* bypassPaths[] = {
        "/proc/self/attr/fscreate",
        "/proc/self/attr/sockcreate",
        nullptr
    };
    const char* bypassContexts[] = {
        "u:r:ksu:s0",
        "u:r:magisk:s0",
        nullptr
    };
    
    for (int p = 0; bypassPaths[p] != nullptr; p++) {
        for (int c = 0; bypassContexts[c] != nullptr; c++) {
            jstring path = env->NewStringUTF(bypassPaths[p]);
            jstring ctx = env->NewStringUTF(bypassContexts[c]);
            jstring probeResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeWriteAttrProbePath(env, clazz, path, ctx);
            const char* probeStr = env->GetStringUTFChars(probeResult, nullptr);
            result += std::string(bypassPaths[p]) + " + " + bypassContexts[c] + " -> " + probeStr + "\n";
            env->ReleaseStringUTFChars(probeResult, probeStr);
            env->DeleteLocalRef(path);
            env->DeleteLocalRef(ctx);
            env->DeleteLocalRef(probeResult);
        }
    }
    
    // 3. Policy scan
    result += "\n[Policy Binary Scan]\n";
    jstring policyResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanPolicy(env, clazz);
    const char* policyStr = env->GetStringUTFChars(policyResult, nullptr);
    result += policyStr;
    result += "\n";
    env->ReleaseStringUTFChars(policyResult, policyStr);
    env->DeleteLocalRef(policyResult);
    
    // 4. Process scan
    result += "\n[Process Scan]\n";
    jstring procResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanProcesses(env, clazz);
    const char* procStr = env->GetStringUTFChars(procResult, nullptr);
    result += procStr;
    result += "\n";
    env->ReleaseStringUTFChars(procResult, procStr);
    env->DeleteLocalRef(procResult);
    
    // 5. Mount scan
    result += "\n[Mount Scan]\n";
    jstring mountResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanMounts(env, clazz);
    const char* mountStr = env->GetStringUTFChars(mountResult, nullptr);
    result += mountStr;
    result += "\n";
    env->ReleaseStringUTFChars(mountResult, mountStr);
    env->DeleteLocalRef(mountResult);
    
    // 6. Env scan
    result += "\n[Environment Scan]\n";
    jstring envResult = Java_org_lsposed_dirtysepolicy_AppZygote_nativeScanEnv(env, clazz);
    const char* envStr = env->GetStringUTFChars(envResult, nullptr);
    result += envStr;
    result += "\n";
    env->ReleaseStringUTFChars(envResult, envStr);
    env->DeleteLocalRef(envResult);
    
    // 7. File scan
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