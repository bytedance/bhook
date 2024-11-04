package com.bytedance.android.bytehook.sample;

public class NativeHacker {
    public static void bytehookHook() {
        nativeBytehookHook();
    }
    public static void bytehookUnhook() {
        nativeBytehookUnhook();
    }
    public static void doDlopen() {
        nativeDoDlopen();
    }
    public static void doDlclose() {
        nativeDoDlclose();
    }
    public static void doRun(boolean benchmark) {
        nativeDoRun(benchmark ? 1 : 0);
    }

    private static native int nativeBytehookHook();
    private static native int nativeBytehookUnhook();
    public static native void nativeDumpRecords(String pathname);

    private static native void nativeDoDlopen();
    private static native void nativeDoDlclose();
    private static native void nativeDoRun(int benchmark);
}
