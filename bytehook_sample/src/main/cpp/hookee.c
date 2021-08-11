#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <jni.h>
#include <android/log.h>

#define HOOKEE_JNI_VERSION    JNI_VERSION_1_6
#define HOOKEE_JNI_CLASS_NAME "com/bytedance/android/bytehook/sample/NativeHookee"
#define HOOKEE_TAG            "bytehook_tag"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_INFO, HOOKEE_TAG, fmt, ##__VA_ARGS__)
#pragma clang diagnostic pop

#pragma clang optimize off
static void hookee_test(JNIEnv *env, jobject thiz)
{
    (void)env, (void)thiz;

    LOG("libhookee.so PRE open()");
    int fd = open("/dev/null", O_RDWR);
    if(fd >= 0) close(fd);
    LOG("libhookee.so POST open()");
}
#pragma clang optimize on

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;

    if(NULL == vm) return JNI_ERR;

    JNIEnv *env;
    if(JNI_OK != (*vm)->GetEnv(vm, (void **)&env, HOOKEE_JNI_VERSION)) return JNI_ERR;
    if(NULL == env || NULL == *env) return JNI_ERR;

    jclass cls;
    if(NULL == (cls = (*env)->FindClass(env, HOOKEE_JNI_CLASS_NAME))) return JNI_ERR;

    JNINativeMethod m[] = {
        {"nativeTest", "()V", (void *)hookee_test}
    };
    if(0 != (*env)->RegisterNatives(env, cls, m, sizeof(m) / sizeof(m[0]))) return JNI_ERR;

    return HOOKEE_JNI_VERSION;
}
