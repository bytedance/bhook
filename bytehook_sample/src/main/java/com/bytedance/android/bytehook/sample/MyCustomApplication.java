package com.bytedance.android.bytehook.sample;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import com.bytedance.shadowhook.ShadowHook;
import com.bytedance.android.bytehook.ByteHook;
import com.bytedance.android.bytehook.systest.SysTest;

public class MyCustomApplication extends Application {

    private String TAG = "bytehook_tag";

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

//        System.loadLibrary("sample"); // test load-before-init

        long start, end;

        // init bytehook
        start = System.currentTimeMillis();
        int r = com.bytedance.android.bytehook.ByteHook.init(new ByteHook.ConfigBuilder()
                    .setMode(ByteHook.Mode.AUTOMATIC)
//                    .setMode(ByteHook.Mode.MANUAL)
                    .setRecordable(true)
                    .setDebug(true)
                    .setShadowhookMode(ShadowHook.Mode.SHARED)
//                    .setShadowhookMode(ShadowHook.Mode.UNIQUE)
                    .setShadowhookRecordable(true)
                    .setShadowhookDebug(true)
                    .build());
        end = System.currentTimeMillis();
        Log.i(TAG, "bytehook init cost: " + (end - start) + " ms, ret = " + r);

        // load hacker
        System.loadLibrary("hacker");

//        System.loadLibrary("sample"); // test load-after-init

        SysTest.init(true, true, true,
                true, true, true);

//        ByteHookAdapter.init(this,
//                new ByteHookAdapter.HostInfo(
//                        "100", "200", "1.2.3", "com.bytedance.android.bytehook.sample", "1234567890",
//                        "https://mon.snssdk.com/monitor/collect/", "https://mon.snssdk.com/monitor/appmonitor/v2/settings"),
//                null);
    }
}
