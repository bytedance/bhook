package com.bytedance.android.bytehook.sample;

public class NativeHacker {
    public static void hook(int type) {
        nativeHook(type);
    }
    public static void unhook() {
        nativeUnhook();
    }

    private static native int nativeHook(int type);
    private static native int nativeUnhook();
}
