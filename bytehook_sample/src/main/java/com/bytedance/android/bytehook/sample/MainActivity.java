package com.bytedance.android.bytehook.sample;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;

public class MainActivity extends AppCompatActivity {
    private int curType = -1; // -1: unhook; 0: hook-single; 1: hook-partial; 2: hook-all

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    private void hookOrUnhook(int newType) {
        if(newType == curType) {
            return;
        }

        if(curType != -1) {
            NativeHacker.unhook();
            curType = -1;
        }

        if(newType != -1) {
            NativeHacker.hook(newType);
            curType = newType;
        }
    }

    public void onRadioButtonClicked(View view) {
        switch(view.getId()) {
            case R.id.radio_hook_single:
                hookOrUnhook(0);
                break;
            case R.id.radio_hook_partial:
                hookOrUnhook(1);
                break;
            case R.id.radio_hook_all:
                hookOrUnhook(2);
                break;
            case R.id.radio_unhook:
                hookOrUnhook(-1);
                break;
        }
    }

    public void onTestClick(View view) {
        NativeHookee.test();
    }
}
