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

#include <jni.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "systest.h"

#define SYSTEST_JNI_VERSION    JNI_VERSION_1_6
#define SYSTEST_JNI_CLASS_NAME "com/bytedance/android/bytehook/systest/SysTest"

static int systest_jni_hook(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  return systest_hook();
}

static int systest_jni_unhook(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  return systest_unhook();
}

static int systest_jni_run(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  return systest_run();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved;

  if (NULL == vm) return JNI_ERR;

  JNIEnv *env;
  if (JNI_OK != (*vm)->GetEnv(vm, (void **)&env, SYSTEST_JNI_VERSION)) return JNI_ERR;
  if (NULL == env || NULL == *env) return JNI_ERR;

  jclass cls;
  if (NULL == (cls = (*env)->FindClass(env, SYSTEST_JNI_CLASS_NAME))) return JNI_ERR;

  JNINativeMethod m[] = {{"nativeHook", "()I", (void *)systest_jni_hook},
                         {"nativeUnhook", "()I", (void *)systest_jni_unhook},
                         {"nativeRun", "()I", (void *)systest_jni_run}};
  if (0 != (*env)->RegisterNatives(env, cls, m, sizeof(m) / sizeof(m[0]))) return JNI_ERR;

  return SYSTEST_JNI_VERSION;
}
