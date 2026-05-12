package org.lsposed.dirtysepolicy;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SELinux;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public final class AppZygote implements ZygotePreload {
    static {
        System.loadLibrary("dirtysepolicy");
    }

    // Native methods for enhanced detection
    static native String nativeWriteAttrProbe(String context);
    static native String nativeWriteAttrProbePath(String path, String context);
    static native String nativeScanMounts();
    static native String nativeScanEnv();
    static native String nativeScanFiles();
    static native String nativeScanPolicy();
    static native String nativeScanProcesses();
    static native String nativeFullScan();
    private static final String KSU_CONTEXT = "u:r:ksu:s0";
    private static final String KSU_FILE_CONTEXT = "u:r:ksu_file:s0";
    private static final String MAGISK_CONTEXT = "u:r:magisk:s0";
    private static final String MAGISK_FILE_CONTEXT = "u:r:magisk_file:s0";
    private static final String LSPOSED_FILE_CONTEXT = "u:r:lsposed_file:s0";
    private static final String XPOSED_DATA_CONTEXT = "u:r:xposed_data:s0";

    static String result = "ERROR: app zygote not called";
    static volatile boolean debug = false;
    static volatile ProcAttrCurrentResult ksuProcAttrCurrentResult = ProcAttrCurrentResult.notRun(KSU_CONTEXT);
    static volatile ProcAttrCurrentResult ksuFileProcAttrCurrentResult = ProcAttrCurrentResult.notRun(KSU_FILE_CONTEXT);
    static volatile ProcAttrCurrentResult magiskProcAttrCurrentResult = ProcAttrCurrentResult.notRun(MAGISK_CONTEXT);
    static volatile ProcAttrCurrentResult magiskFileProcAttrCurrentResult = ProcAttrCurrentResult.notRun(MAGISK_FILE_CONTEXT);
    static volatile ProcAttrCurrentResult lsposedFileProcAttrCurrentResult = ProcAttrCurrentResult.notRun(LSPOSED_FILE_CONTEXT);
    static volatile ProcAttrCurrentResult xposedDataProcAttrCurrentResult = ProcAttrCurrentResult.notRun(XPOSED_DATA_CONTEXT);

    private static Map<Integer, String> scanFd() {
        var result = new HashMap<Integer, String>();
        for (var f: new File("/proc/self/fd").listFiles()) {
            var fdNum = Integer.parseInt(f.getName());
            try {
                var path = Os.readlink(f.getAbsolutePath());
                result.put(fdNum, path);
            } catch (Throwable ignored) {
            }
        }
        return result;
    }

    private static void doDetect() {
        if (!SELinux.isSELinuxEnabled()) {
            result = "ERROR: SELinux is disabled";
            return;
        }
        var context = SELinux.getContext();
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
            result = "ERROR: unexpected SELinux context: " + context;
            return;
        }
        var pidContext = SELinux.getPidContext(Os.getpid());
        if (!context.equals(pidContext)) {
            result = "ERROR: PID context mismatch: " + pidContext;
            return;
        }
        var procContext = SELinux.getFileContext("/proc/self");
        if (!context.equals(procContext)) {
            result = "ERROR: /proc/self context mismatch: " + procContext;
            return;
        }
        if (!SELinux.isSELinuxEnforced()) {
            result = "ERROR: SELinux is permissive";
            return;
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:isolated_app:s0", "process", "dyntransition")) {
            result = "ERROR: cannot check SELinux access";
            return;
        }
        
        var sb = new StringBuilder();
        
        // Phase 1: Direct procattr probes (may be blocked by KSU PR#3459)
        ksuProcAttrCurrentResult = runProcAttrCurrentProbe(KSU_CONTEXT);
        ksuFileProcAttrCurrentResult = runProcAttrCurrentProbe(KSU_FILE_CONTEXT);
        magiskProcAttrCurrentResult = runProcAttrCurrentProbe(MAGISK_CONTEXT);
        magiskFileProcAttrCurrentResult = runProcAttrCurrentProbe(MAGISK_FILE_CONTEXT);
        lsposedFileProcAttrCurrentResult = runProcAttrCurrentProbe(LSPOSED_FILE_CONTEXT);
        xposedDataProcAttrCurrentResult = runProcAttrCurrentProbe(XPOSED_DATA_CONTEXT);
        
        if (ksuProcAttrCurrentResult.detected() || ksuFileProcAttrCurrentResult.detected()) {
            sb.append("found KernelSU; ");
        }
        if (magiskProcAttrCurrentResult.detected() || magiskFileProcAttrCurrentResult.detected()) {
            sb.append("found Magisk; ");
        }
        if (lsposedFileProcAttrCurrentResult.detected()) {
            sb.append("found LSPosed; ");
        }
        if (xposedDataProcAttrCurrentResult.detected()) {
            sb.append("found Xposed; ");
        }
        
        // Phase 2: Procattr bypass probes (bypasses KSU setprocattr hook)
        // KSU PR#3459 only hooks "current", not "fscreate"/"sockcreate"/"keycreate"
        var ksuFscreate = runProcAttrPathProbe("/proc/self/attr/fscreate", KSU_CONTEXT);
        var ksuSockcreate = runProcAttrPathProbe("/proc/self/attr/sockcreate", KSU_CONTEXT);
        var magiskFscreate = runProcAttrPathProbe("/proc/self/attr/fscreate", MAGISK_CONTEXT);
        var magiskSockcreate = runProcAttrPathProbe("/proc/self/attr/sockcreate", MAGISK_CONTEXT);
        
        if (ksuFscreate.detected() || ksuSockcreate.detected()) {
            sb.append("found KernelSU (procattr bypass); ");
        }
        if (magiskFscreate.detected() || magiskSockcreate.detected()) {
            sb.append("found Magisk (procattr bypass); ");
        }
        
        // Phase 3: SELinux permission audits
        if (SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            sb.append("system_server can execmem; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:fsck_untrusted:s0", "u:r:fsck_untrusted:s0", "capability", "sys_admin")) {
            sb.append("neverallow violated; ");
        }
        if (Build.TYPE.equals("user") && SELinux.checkSELinuxAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
            sb.append("found AOSP su in user build; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:adbd:s0", "u:r:adbroot:s0", "binder", "call")) {
            sb.append("found adb_root; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:r:magisk:s0", "binder", "call")) {
            sb.append("found Magisk; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:ksu_file:s0", "file", "read")) {
            sb.append("found KernelSU; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file", "read")) {
            sb.append("found LSPosed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:xposed_data:s0", "file", "read")) {
            sb.append("found Xposed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
            sb.append("found ZygiskNext; ");
        }

        // Phase 4: Native layer detection (bypasses Java hooks)
        String nativeResult = nativeFullScan();
        if (nativeResult.contains("DETECTED")) {
            sb.append("native scan detected artifacts; ");
        }
        
        // Phase 5: Policy binary scan (bypasses KSU PR#3459 completely)
        String policyResult = nativeScanPolicy();
        if (policyResult.contains("DETECTED")) {
            sb.append("policy scan detected; ");
        }
        
        // Phase 6: Process scan (find magiskd/zygiskd regardless of domain name)
        String procResult = nativeScanProcesses();
        if (procResult.contains("DETECTED")) {
            sb.append("suspicious processes detected; ");
        }

        // Phase 7: Side-effect scans
        String mountResult = nativeScanMounts();
        if (mountResult.contains("DETECTED")) {
            sb.append("magisk mounts detected; ");
        }
        String envResult = nativeScanEnv();
        if (envResult.contains("DETECTED")) {
            sb.append("magisk env detected; ");
        }
        String fileResult = nativeScanFiles();
        if (fileResult.contains("DETECTED")) {
            sb.append("magisk files detected; ");
        }

        if (sb.length() == 0) {
            result = "OK: no dirty sepolicy found";
        } else {
            result = "WARNING: " + sb;
        }
        if (debug) {
            result = "\n\n\n\n\n\n" + ksuProcAttrCurrentResult.formatMultiline("A ksu") + "\n\n"
                    + ksuFileProcAttrCurrentResult.formatMultiline("A ksu_file") + "\n\n"
                    + magiskProcAttrCurrentResult.formatMultiline("A magisk") + "\n\n"
                    + magiskFileProcAttrCurrentResult.formatMultiline("A magisk_file") + "\n\n"
                    + lsposedFileProcAttrCurrentResult.formatMultiline("A lsposed_file") + "\n\n"
                    + xposedDataProcAttrCurrentResult.formatMultiline("A xposed_data") + "\n\n"
                    + "Native Scan:\n" + nativeFullScan() + "\n\n"
                    + result + "\n\n\n\n";
        }
    }

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        debug = (appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        var uid = Os.getuid();
        if (uid != appInfo.uid) {
            result = "ERROR: UID mismatch: " + uid + " != app uid " + appInfo.uid;
            return;
        }
        var preFds = scanFd();
        try {
            doDetect();
        } finally {
            // find selinux netlink socket and dup it with a valid fd
            // https://cs.android.com/android/platform/superproject/+/android-11.0.0_r21:external/selinux/libselinux/src/checkAccess.c;l=22
            // SELinux netlink socket may be created when selinux_check_access is called
            // Before Android 13, this socket is always created
            // This fd will be rejected when fork new app process, and crash app zygote
            // App zygote can mark fds created during doPreload, but only after A12
            // https://cs.android.com/android/platform/superproject/+/android-12.0.0_r3:frameworks/base/core/java/com/android/internal/os/AppZygoteInit.java;l=94-96;drc=ff6ac69e69423107a626a00c3e01e9bf5eb2814c
            // https://cs.android.com/android/platform/superproject/+/android-11.0.0_r21:frameworks/base/core/java/com/android/internal/os/AppZygoteInit.java;l=79;drc=fb7caa96f9511273ef32e1e80b740b28ca91a536
            var postFds = scanFd();
            boolean found = false;
            for (var e: postFds.entrySet()) {
                if (!e.getValue().startsWith("socket:[")) continue;
                if (preFds.containsKey(e.getKey()) && preFds.get(e.getKey()).equals(e.getValue())) {
                    continue;
                }
                Log.d("DirtySepolicy", "selinux netlink socket fd: " + e.getKey());
                found = true;
                try {
                    var newFd = Os.open("/dev/null", OsConstants.O_RDWR, 0);
                    Os.dup2(newFd, e.getKey());
                    Os.close(newFd);
                } catch (Throwable t) {
                    Log.e("DirtySepolicy", "dup selinux netlink socket fd err: " + e.getKey(), t);
                }
            }
            if (!found) {
                // It's normal to be not found after A13
                Log.w("DirtySepolicy", "selinux netlink socket fd not found! ");
            }
        }
    }

    private static ProcAttrCurrentResult runProcAttrCurrentProbe(String targetContext) {
        return runProcAttrPathProbe("/proc/self/attr/current", targetContext);
    }

    private static ProcAttrCurrentResult runProcAttrPathProbe(String path, String targetContext) {
        try (var out = new FileOutputStream(path)) {
            Os.write(out.getFD(), targetContext.getBytes(StandardCharsets.UTF_8), 0, targetContext.getBytes(StandardCharsets.UTF_8).length);
            return ProcAttrCurrentResult.success(targetContext, "write succeeded");
        } catch (SecurityException e) {
            return ProcAttrCurrentResult.security(targetContext, e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (IOException e) {
            return classifyIOException(targetContext, e);
        } catch (ErrnoException e) {
            return classifyErrnoException(targetContext, e);
        }
    }

    private static ProcAttrCurrentResult classifyIOException(String targetContext, IOException e) {
        var message = e.getMessage();
        var detail = e.getClass().getSimpleName() + ": " + message;
        if (message != null && message.toLowerCase().contains("invalid argument")) {
            return ProcAttrCurrentResult.einval(targetContext, detail);
        }
        return ProcAttrCurrentResult.nonEinval(targetContext, detail);
    }

    private static ProcAttrCurrentResult classifyErrnoException(String targetContext, ErrnoException e) {
        var detail = e.getClass().getSimpleName() + ": errno=" + e.errno + ", " + e.getMessage();
        if (e.errno == OsConstants.EINVAL) {
            return ProcAttrCurrentResult.einval(targetContext, detail);
        }
        return ProcAttrCurrentResult.nonEinval(targetContext, detail);
    }
}


