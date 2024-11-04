package com.bytedance.android.bytehook.sample;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.Intent;
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
    HookType hookType = HookType.WITHOUT;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mThreadNum = getIntent().getIntExtra("threadnum", 100);
        mCallNum = mTotalNum / mThreadNum;

        int benchmarkType = getIntent().getIntExtra("benchmark", 0);
        if(benchmarkType != 0) {
            switch (benchmarkType) {
                case 1:
                    changeHookType(HookType.BYTEHOOK);
                    break;
                case 4:
                    break;
            }

            try {
                Thread.sleep(500);
            } catch (InterruptedException ignored) {
            }

            benchmarkTest();
        }
    }

    public void onRadioButtonClicked(View view) {
        switch(view.getId()) {
            case R.id.radio_without:
                changeHookType(HookType.WITHOUT);
                break;
            case R.id.radio_bytehook:
                changeHookType(HookType.BYTEHOOK);
//                System.loadLibrary("sample"); // test load-after-hook
                break;
        }
    }

    public void onTestClick(View view) {
        Log.i(TAG, "onClick pre strlen");
        NativeHacker.doRun(false);
        Log.i(TAG, "onClick post strlen");
    }

    public void onBenchmarkClick(View view) {
        findViewById(R.id.benchmarkButton).setEnabled(false);
        benchmarkTest();
    }

    public void onDlopenClick(View view) {
        NativeHacker.doDlopen();
    }

    public void onDlcloseClick(View view) {
        NativeHacker.doDlclose();
    }

    private enum HookType {
        WITHOUT, BYTEHOOK, NONHOOK
    }

    private String getHookTypeName() {
        switch (hookType) {
            case WITHOUT:
                return "without-hook";
            case BYTEHOOK:
                return "bytehook";
            default:
                return "unknown";
        }
    }

    private void changeHookType(HookType newHookType) {
        if(hookType == newHookType) {
            return;
        }

        switch (hookType) {
            case WITHOUT:
                break;
            case BYTEHOOK:
                NativeHacker.bytehookUnhook();
                break;
        }

        hookType = newHookType;

        switch (hookType) {
            case WITHOUT:
                break;
            case BYTEHOOK:
                NativeHacker.bytehookHook();
                break;
        }
    }

    //
    // benchmark test
    //
    private final int mTotalNum = 10000000;
    private int mThreadNum = 100;
    private int mCallNum = 100000;
    private long[] mStartTime;
    private long[] mEndTime;
    private AtomicInteger unfinishedThreadNum = new AtomicInteger(0);

    private void benchmarkTest() {
        if(!unfinishedThreadNum.compareAndSet(0, mThreadNum)) {
            Log.i(TAG, "The last benchmark test has not been completed.");
            return;
        }

        final int pid = android.os.Process.myPid();

        final String fHookType = getHookTypeName();

        mStartTime = new long[mThreadNum];
        mEndTime = new long[mThreadNum];

        for(int i = 0; i < mThreadNum; i++) {
            final int threadIdx = i;
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    mStartTime[threadIdx] = System.currentTimeMillis();

                    for (int i = 0; i < mCallNum; i++) {
                        NativeHacker.doRun(true);
                    }

                    mEndTime[threadIdx] = System.currentTimeMillis();

                    if(unfinishedThreadNum.decrementAndGet() == 0) {
                        long totalCost = 0;
                        long maxCost = 0;
                        for(int i = 0; i < mThreadNum; i++) {
                            long cost = mEndTime[i] - mStartTime[i];
                            totalCost += cost;
                            if (cost > maxCost) {
                                maxCost = cost;
                            }
                            //Log.i(TAG, "Thread " + i + " cost: " + cost + " ms");
                        }
                        long avgCost = totalCost / mThreadNum;
                        long qps = (long)((double)mTotalNum / ((double)avgCost / 1000.0));
                        Log.i(TAG, fHookType + " (PID: " + pid + ") [benchmark test] threads num: " + mThreadNum + ", calls/thread: " + mCallNum);
                        Log.i(TAG, fHookType + " (PID: " + pid + ") [benchmark test] max cost: " + maxCost + " ms, avg cost: " + avgCost + " ms, qps: " + qps);
                        Log.i(TAG, fHookType + " (PID: " + pid + ") [benchmark test] finished");

                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                findViewById(R.id.benchmarkButton).setEnabled(true);
                            }
                        });
                    }
                }
            });
            thread.setName("test_thd_" + i);
            thread.start();
        }
    }

    public void onSystemTestHookClick(View view) {
        SysTest.hook();
    }

    public void onSystemTestUnhookClick(View view) {
        SysTest.unhook();
    }

    public void onSystemTestRunClick(View view) {
        SysTest.run();
    }


    public void onGetRecordsClick(View view) {
        String records = ByteHook.getRecords();
//        String records = ByteHook.getRecords(ByteHook.RecordItem.CALLER_LIB_NAME, ByteHook.RecordItem.OP, ByteHook.RecordItem.LIB_NAME, ByteHook.RecordItem.SYM_NAME, ByteHook.RecordItem.ERRNO, ByteHook.RecordItem.STUB);
        if (records != null) {
            for (String line : records.split("\n")) {
                Log.i(TAG, line);
            }
        }
    }

    public void onDumpRecordsClick(View view) {
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
}
