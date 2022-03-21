// Copyright (c) 2020-2021 ByteDance, Inc.
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

public class ByteHook {

    private static boolean inited = false;
    private static int initStatus = 1; // uninit
    private static long initCostMs = -1;
    private static final String libName = "bytehook";
    private static final ILibLoader defaultLibLoader = null;
    private static final int defaultMode = Mode.AUTOMATIC.getValue();
    private static final boolean defaultDebug = false;

    public static int init() {
        if (inited) {
            return initStatus;
        }

        return init(new ConfigBuilder().build());
    }

    public static synchronized int init(Config config) {
        if (inited) {
            return initStatus;
        }
        inited = true;

        long start = System.currentTimeMillis();

        try {
            if (config.getLibLoader() == null) {
                System.loadLibrary(libName);
            } else {
                config.getLibLoader().loadLibrary(libName);
            }
        } catch (Throwable ignored) {
            initStatus = 100; // load library failed
            initCostMs = System.currentTimeMillis() - start;
            return initStatus;
        }

        try {
            initStatus = nativeInit(config.getMode(), config.getDebug());
        } catch (Throwable ignored) {
            initStatus = 101; // call init() failed
        }

        initCostMs = System.currentTimeMillis() - start;
        return initStatus;
    }

    public static int addIgnore(String callerPathName) {
        if (initStatus == 0) {
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

    public static void setDebug(boolean debug) {
        if (initStatus == 0) {
            nativeSetDebug(debug);
        }
    }

    public static String getRecords(RecordItem... recordItems) {
        if (initStatus == 0) {
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
        if (initStatus == 0) {
            return nativeGetArch();
        }
        return "unknown";
    }

    public static class Config {
        private ILibLoader libLoader;
        private int mode;
        private boolean debug;

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
    }

    public static class ConfigBuilder {

        private ILibLoader libLoader = defaultLibLoader;
        private int mode = defaultMode;
        private boolean debug = defaultDebug;

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

        public Config build() {
            Config config = new Config();
            config.setLibLoader(libLoader);
            config.setMode(mode);
            config.setDebug(debug);
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

    private static native int nativeInit(int mode, boolean debug);

    private static native int nativeAddIgnore(String callerPathName);

    private static native void nativeSetDebug(boolean debug);

    private static native String nativeGetRecords(int itemFlags);

    private static native String nativeGetArch();
}
