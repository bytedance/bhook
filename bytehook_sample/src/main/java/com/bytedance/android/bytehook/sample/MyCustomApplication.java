package com.bytedance.android.bytehook.sample;

import android.app.Application;
import android.content.Context;

import com.bytedance.android.bytehook.systest.SysTest;

public class MyCustomApplication extends Application {
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

//        System.loadLibrary("sample"); // test load-before-init
        System.loadLibrary("hacker");

        SysTest.init(true, true, true,
                true, true, true);
    }
}
