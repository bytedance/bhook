// Copyright (c) 2020-2024 ByteDance, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Created by Kelun Cai (caikelun@bytedance.com) on 2024-09-20.

package com.bytedance.android.bytehook.systest;

import com.bytedance.android.bytehook.ByteHook;
import com.bytedance.shadowhook.ShadowHook;

public class SysTest {

    private static boolean inited = false;
    private static int initStatus = 200; // uninit
    private static final String libName = "bytehooksystest";

    public static int init(boolean automaticMode, boolean debuggable, boolean recordable,
                            boolean shadowhookSharedMode, boolean shadowhookDebuggable, boolean shadowhookRecordable) {
        if (inited) {
            return initStatus;
        }
        inited = true;

        // init bytehook
        initStatus = ByteHook.init(new ByteHook.ConfigBuilder()
                .setMode(automaticMode ? ByteHook.Mode.AUTOMATIC : ByteHook.Mode.MANUAL)
                .setDebug(debuggable)
                .setRecordable(recordable)
                .setShadowhookMode(shadowhookSharedMode ? ShadowHook.Mode.SHARED : ShadowHook.Mode.UNIQUE)
                .setShadowhookDebug(shadowhookDebuggable)
                .setShadowhookRecordable(shadowhookRecordable)
                .build());
        if(0 != initStatus) {
            return initStatus;
        }

        // load libbytehooksystest.so
        try {
            System.loadLibrary(libName);
        } catch (Throwable ignored) {
            initStatus = 201;
            return initStatus;
        }

        // test ignore
        //ByteHook.addIgnore("libart.so");

        initStatus = 0;
        return initStatus;
    }

    public static int hook() {
        if (initStatus != 0) {
            return initStatus;
        }

        return nativeHook();
    }

    public static int unhook() {
        if (initStatus != 0) {
            return initStatus;
        }

        return nativeUnhook();
    }

    public static int run() {
        if (initStatus != 0) {
            return initStatus;
        }

        return nativeRun();
    }

    public static native int nativeHook();
    public static native int nativeUnhook();
    public static native int nativeRun();
}
