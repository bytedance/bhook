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

// Created by caikelun (caikelun@bytedance.com) on 2020-06-02.

package com.bytedance.android.bytehook;

import com.bytedance.shadowhook.ShadowHook;

public class ByteHook {
    private static final int ERRNO_OK = 0;
    private static final int ERRNO_UNINIT = 1;
    private static final int ERRNO_LOAD_LIBRARY_EXCEPTION = 100;
    private static final int ERRNO_INIT_EXCEPTION = 101;

    private static boolean inited = false;
    private static int initStatus = ERRNO_UNINIT;
    private static long initCostMs = -1;
    private static final String libName = "bytehook";

    private static final ILibLoader defaultLibLoader = null;
    private static final int defaultMode = Mode.AUTOMATIC.getValue();
    private static final boolean defaultDebug = false;
    private static final boolean defaultRecordable = false;

    private static final ShadowHook.ILibLoader defaultShadowhookLibLoader = null;
    private static final ShadowHook.Mode defaultShadowhookMode = ShadowHook.Mode.SHARED;
    private static final boolean defaultShadowhookDebug = false;
    private static final boolean defaultShadowhookRecordable = false;

    public static String getVersion() {
        return nativeGetVersion();
    }

    public static int init() {
        return init(null);
    }

    public static synchronized int init(Config config) {
        if (inited) {
            return initStatus;
        }
        inited = true;

        long start = System.currentTimeMillis();

        if (config == null) {
            //use default parameters
            config = new ConfigBuilder().build();
        }

        // init shadowhook
        ShadowHook.init(new ShadowHook.ConfigBuilder()
                .setLibLoader(config.getShadowhookLibLoader())
                .setMode(config.getShadowhookMode())
                .setDebuggable(config.getShadowhookDebug())
                .setRecordable(config.getShadowhookRecordable())
                .build());

        // load libbytehook.so
        try {
            if (config.getLibLoader() == null) {
                System.loadLibrary(libName);
            } else {
                config.getLibLoader().loadLibrary(libName);
            }
        } catch (Throwable ignored) {
            initStatus = ERRNO_LOAD_LIBRARY_EXCEPTION;
            initCostMs = System.currentTimeMillis() - start;
            return initStatus;
        }

        // call native bytehook_init()
        try {
            initStatus = nativeInit(config.getMode(), config.getDebug());
        } catch (Throwable ignored) {
            initStatus = ERRNO_INIT_EXCEPTION;
        }

        // call native bytehook_set_recordable()
        if (config.getRecordable()) {
            try {
                nativeSetRecordable(config.getRecordable());
            } catch (Throwable ignored) {
                initStatus = ERRNO_INIT_EXCEPTION;
            }
        }

        initCostMs = System.currentTimeMillis() - start;
        return initStatus;
    }

    public static int addIgnore(String callerPathName) {
        if (initStatus == ERRNO_OK) {
            return nativeAddIgnore(callerPathName);
        }
        return initStatus;
    }

    public static int getInitErrno() {
        return initStatus;
    }

    public static long getInitCostMs() {
        return initCostMs;
    }

    public static Mode getMode() {
        if (initStatus == ERRNO_OK) {
            return Mode.AUTOMATIC.getValue() == nativeGetMode() ? Mode.AUTOMATIC : Mode.MANUAL;
        }
        return Mode.AUTOMATIC;
    }

    public static boolean getDebug() {
        if (initStatus == ERRNO_OK) {
            return nativeGetDebug();
        }
        return defaultDebug;
    }

    public static void setDebug(boolean debug) {
        if (initStatus == ERRNO_OK) {
            nativeSetDebug(debug);
        }
    }

    public static boolean getRecordable() {
        if (initStatus == ERRNO_OK) {
            return nativeGetRecordable();
        }
        return defaultRecordable;
    }

    public static void setRecordable(boolean recordable) {
        if (initStatus == ERRNO_OK) {
            nativeSetRecordable(recordable);
        }
    }

    public static String getRecords(RecordItem... recordItems) {
        if (initStatus == ERRNO_OK) {
            int itemFlags = 0;
            for (RecordItem recordItem : recordItems) {
                switch (recordItem) {
                    case TIMESTAMP:
                        itemFlags |= recordItemTimestamp;
                        break;
                    case CALLER_LIB_NAME:
                        itemFlags |= recordItemCallerLibName;
                        break;
                    case OP:
                        itemFlags |= recordItemOp;
                        break;
                    case LIB_NAME:
                        itemFlags |= recordItemLibName;
                        break;
                    case SYM_NAME:
                        itemFlags |= recordItemSymName;
                        break;
                    case NEW_ADDR:
                        itemFlags |= recordItemNewAddr;
                        break;
                    case ERRNO:
                        itemFlags |= recordItemErrno;
                        break;
                    case STUB:
                        itemFlags |= recordItemStub;
                        break;
                    default:
                        break;
                }
            }

            if (itemFlags == 0) {
                itemFlags = recordItemAll;
            }

            return nativeGetRecords(itemFlags);
        }
        return null;
    }

    public static String getArch() {
        if (initStatus == ERRNO_OK) {
            return nativeGetArch();
        }
        return "unknown";
    }

    public static class Config {
        private ILibLoader libLoader;
        private int mode;
        private boolean debug;
        private boolean recordable;
        private ShadowHook.ILibLoader shadowhookLibLoader;
        private ShadowHook.Mode shadowhookMode;
        private boolean shadowhookDebug;
        private boolean shadowhookRecordable;

        public Config() {
        }

        public void setLibLoader(ILibLoader libLoader) {
            this.libLoader = libLoader;
        }

        public ILibLoader getLibLoader() {
            return this.libLoader;
        }

        public void setMode(int mode) {
            this.mode = mode;
        }

        public int getMode() {
            return this.mode;
        }

        public void setDebug(boolean debug) {
            this.debug = debug;
        }

        public boolean getDebug() {
            return this.debug;
        }

        public void setRecordable(boolean recordable) {
            this.recordable = recordable;
        }

        public boolean getRecordable() {
            return this.recordable;
        }

        public void setShadowhookLibLoader(ShadowHook.ILibLoader libLoader) {
            this.shadowhookLibLoader = libLoader;
        }

        public ShadowHook.ILibLoader getShadowhookLibLoader() {
            return this.shadowhookLibLoader;
        }

        public void setShadowhookMode(ShadowHook.Mode mode) {
            this.shadowhookMode = mode;
        }

        public ShadowHook.Mode getShadowhookMode() {
            return this.shadowhookMode;
        }

        public void setShadowhookDebug(boolean debug) {
            this.shadowhookDebug = debug;
        }

        public boolean getShadowhookDebug() {
            return this.shadowhookDebug;
        }

        public void setShadowhookRecordable(boolean recordable) {
            this.shadowhookRecordable = recordable;
        }

        public boolean getShadowhookRecordable() {
            return this.shadowhookRecordable;
        }
    }

    public static class ConfigBuilder {

        private ILibLoader libLoader = defaultLibLoader;
        private int mode = defaultMode;
        private boolean debug = defaultDebug;
        private boolean recordable = defaultRecordable;
        private ShadowHook.ILibLoader shadowhookLibLoader = defaultShadowhookLibLoader;
        private ShadowHook.Mode shadowhookMode = defaultShadowhookMode;
        private boolean shadowhookDebug = defaultShadowhookDebug;
        private boolean shadowhookRecordable = defaultShadowhookRecordable;

        public ConfigBuilder() {
        }

        public ConfigBuilder setLibLoader(ILibLoader libLoader) {
            this.libLoader = libLoader;
            return this;
        }

        public ConfigBuilder setMode(Mode mode) {
            this.mode = mode.getValue();
            return this;
        }

        public ConfigBuilder setDebug(boolean debug) {
            this.debug = debug;
            return this;
        }

        public ConfigBuilder setRecordable(boolean recordable) {
            this.recordable = recordable;
            return this;
        }

        public ConfigBuilder setShadowhookLibLoader(ShadowHook.ILibLoader libLoader) {
            this.shadowhookLibLoader = libLoader;
            return this;
        }

        public ConfigBuilder setShadowhookMode(ShadowHook.Mode mode) {
            this.shadowhookMode = mode;
            return this;
        }

        public ConfigBuilder setShadowhookDebug(boolean debug) {
            this.shadowhookDebug = debug;
            return this;
        }

        public ConfigBuilder setShadowhookRecordable(boolean recordable) {
            this.shadowhookRecordable = recordable;
            return this;
        }

        public Config build() {
            Config config = new Config();
            config.setLibLoader(libLoader);
            config.setMode(mode);
            config.setDebug(debug);
            config.setRecordable(recordable);
            config.setShadowhookLibLoader(shadowhookLibLoader);
            config.setShadowhookMode(shadowhookMode);
            config.setShadowhookDebug(shadowhookDebug);
            config.setShadowhookRecordable(shadowhookRecordable);
            return config;
        }
    }

    public enum Mode {
        AUTOMATIC(0), MANUAL(1);

        private final int value;
        Mode(int value) {
            this.value = value;
        }

        int getValue() {
            return value;
        }
    }

    private static final int recordItemAll = 0b11111111;
    private static final int recordItemTimestamp = 1;
    private static final int recordItemCallerLibName = 1 << 1;
    private static final int recordItemOp = 1 << 2;
    private static final int recordItemLibName = 1 << 3;
    private static final int recordItemSymName = 1 << 4;
    private static final int recordItemNewAddr = 1 << 5;
    private static final int recordItemErrno = 1 << 6;
    private static final int recordItemStub = 1 << 7;

    public enum RecordItem {
        TIMESTAMP,
        CALLER_LIB_NAME,
        OP,
        LIB_NAME,
        SYM_NAME,
        NEW_ADDR,
        ERRNO,
        STUB
    }

    private static native String nativeGetVersion();
    private static native int nativeInit(int mode, boolean debug);
    private static native int nativeAddIgnore(String callerPathName);
    private static native int nativeGetMode();
    private static native boolean nativeGetDebug();
    private static native void nativeSetDebug(boolean debug);
    private static native boolean nativeGetRecordable();
    private static native void nativeSetRecordable(boolean recordable);
    private static native String nativeGetRecords(int itemFlags);
    private static native String nativeGetArch();
}
