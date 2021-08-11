package com.bytedance.android.bytehook.sample;

public class NativeHookee {
    public static void test() {
        nativeTest();
    }

    private static native void nativeTest();
}
