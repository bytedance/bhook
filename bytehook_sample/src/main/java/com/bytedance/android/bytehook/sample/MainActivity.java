package com.bytedance.android.bytehook.sample;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.RadioButton;

import com.bytedance.android.bytehook.ByteHook;
import com.bytedance.android.bytehook.systest.SysTest;


import java.io.BufferedReader;
import java.io.FileReader;
import java.util.concurrent.atomic.AtomicInteger;

public class MainActivity extends AppCompatActivity {

    private String TAG = "bytehook_tag";
    boolean isHooked = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        findViewById(R.id.unitTestHook).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (!isHooked) {
                    NativeHacker.bytehookHook();
                    isHooked = true;
                }
            }
        });

        findViewById(R.id.unitTestUnhook).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (isHooked) {
                    NativeHacker.bytehookUnhook();
                    isHooked = false;
                }
            }
        });

        findViewById(R.id.unitTestLoad).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                NativeHacker.doDlopen();
            }
        });

        findViewById(R.id.unitTestUnload).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                NativeHacker.doDlclose();
            }
        });

        findViewById(R.id.unitTestRun).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.i(TAG, "onClick pre strlen()");
                NativeHacker.doRun();
                Log.i(TAG, "onClick post strlen()");
            }
        });

        findViewById(R.id.systemtestTestHook).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                SysTest.hook();
            }
        });

        findViewById(R.id.systemtestTestUnhook).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                SysTest.unhook();
            }
        });

        findViewById(R.id.systemtestTestRun).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                SysTest.run();
            }
        });

        findViewById(R.id.getRecords).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String records = ByteHook.getRecords();
//                String records = ByteHook.getRecords(ByteHook.RecordItem.CALLER_LIB_NAME, ByteHook.RecordItem.OP, ByteHook.RecordItem.LIB_NAME, ByteHook.RecordItem.SYM_NAME, ByteHook.RecordItem.ERRNO, ByteHook.RecordItem.STUB);
                if (records != null) {
                    for (String line : records.split("\n")) {
                        Log.i(TAG, line);
                    }
                }
            }
        });

        findViewById(R.id.dumpRecords).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String pathname = getApplicationContext().getFilesDir() + "/bytehook_records.txt";
                NativeHacker.nativeDumpRecords(pathname);

                BufferedReader br = null;
                try {
                    br = new BufferedReader(new FileReader(pathname));
                    String line;
                    while ((line = br.readLine()) != null) {
                        Log.i(TAG, line);
                    }
                } catch (Throwable ignored) {
                } finally {
                    if (br != null) {
                        try {
                            br.close();
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        });
    }
}
