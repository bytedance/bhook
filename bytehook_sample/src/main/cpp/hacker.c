#include <android/api-level.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "bytehook.h"
#include "hacker_bytehook.h"

#define HACKER_JNI_VERSION    JNI_VERSION_1_6
#define HACKER_JNI_CLASS_NAME "com/bytedance/android/bytehook/sample/NativeHacker"

static int hacker_jni_bytehook_hook(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  return hacker_bytehook_hook();
}

static int hacker_jni_bytehook_unhook(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  return hacker_bytehook_unhook();
}

static void hacker_jni_dump_records(JNIEnv *env, jobject thiz, jstring pathname) {
  (void)thiz;

  const char *c_pathname = (*env)->GetStringUTFChars(env, pathname, 0);
  if (NULL == c_pathname) return;

  int fd = open(c_pathname, O_CREAT | O_WRONLY | O_CLOEXEC | O_TRUNC | O_APPEND, S_IRUSR | S_IWUSR);
  if (fd >= 0) {
    bytehook_dump_records(fd, BYTEHOOK_RECORD_ITEM_ALL);
    //        bytehook_dump_records(fd, BYTEHOOK_RECORD_ITEM_CALLER_LIB_NAME | BYTEHOOK_RECORD_ITEM_OP |
    //        BYTEHOOK_RECORD_ITEM_LIB_NAME | BYTEHOOK_RECORD_ITEM_SYM_NAME | BYTEHOOK_RECORD_ITEM_ERRNO |
    //        BYTEHOOK_RECORD_ITEM_STUB);
    close(fd);
  }

  (*env)->ReleaseStringUTFChars(env, pathname, c_pathname);
}

static void *libsample_handle = NULL;
typedef void (*sample_test_strlen_t)(void);
static sample_test_strlen_t sample_test_strlen = NULL;

static void hacker_jni_do_dlopen(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  //  void *libc = dlopen("libc.so", RTLD_NOW);
  //  if (NULL != libc) dlclose(libc);

  if (NULL == libsample_handle) {
    libsample_handle = dlopen("libsample.so", RTLD_NOW);
    if (NULL != libsample_handle) {
      sample_test_strlen = (sample_test_strlen_t)dlsym(libsample_handle, "sample_test_strlen");
    }
  }
}

static void hacker_jni_do_run(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  if (NULL != sample_test_strlen) sample_test_strlen();
}

static void hacker_jni_do_dlclose(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  //  void *libc = dlopen("libc.so", RTLD_NOW);
  //  if (NULL != libc) dlclose(libc);

  if (NULL != libsample_handle) {
    sample_test_strlen = NULL;
    dlclose(libsample_handle);
    libsample_handle = NULL;
  }
}

static JNINativeMethod hacker_jni_methods[] = {
    {"nativeBytehookHook", "()I", (void *)hacker_jni_bytehook_hook},
    {"nativeBytehookUnhook", "()I", (void *)hacker_jni_bytehook_unhook},
    {"nativeDumpRecords", "(Ljava/lang/String;)V", (void *)hacker_jni_dump_records},
    {"nativeDoDlopen", "()V", (void *)hacker_jni_do_dlopen},
    {"nativeDoDlclose", "()V", (void *)hacker_jni_do_dlclose},
    {"nativeDoRun", "()V", (void *)hacker_jni_do_run}};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  JNIEnv *env;
  jclass cls;

  (void)reserved;

  if (NULL == vm) return JNI_ERR;
  if (JNI_OK != (*vm)->GetEnv(vm, (void **)&env, HACKER_JNI_VERSION)) return JNI_ERR;
  if (NULL == env || NULL == *env) return JNI_ERR;
  if (NULL == (cls = (*env)->FindClass(env, HACKER_JNI_CLASS_NAME))) return JNI_ERR;
  if (0 != (*env)->RegisterNatives(env, cls, hacker_jni_methods,
                                   sizeof(hacker_jni_methods) / sizeof(hacker_jni_methods[0])))
    return JNI_ERR;

  return HACKER_JNI_VERSION;
}
