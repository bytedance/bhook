#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/system_properties.h>
#include <android/api-level.h>
#include <android/log.h>
#include <sys/time.h>
#include "hacker_bytehook.h"
#include "bytehook.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define LOG(fmt, ...)  __android_log_print(ANDROID_LOG_INFO, "bytehook_tag", fmt, ##__VA_ARGS__)
#pragma clang diagnostic pop

//#ifndef __LP64__
//#define HACKER_PATHNAME_LIBC     "/system/lib/libc.so"
//#define HACKER_PATHNAME_LIBC_Q   "/apex/com.android.runtime/lib/bionic/libc.so"
//#else
//#define HACKER_PATHNAME_LIBC     "/system/lib64/libc.so"
//#define HACKER_PATHNAME_LIBC_Q   "/apex/com.android.runtime/lib64/bionic/libc.so"
//#endif
//
//#define HACKER_LIBC (android_get_device_api_level() < __ANDROID_API_Q__ ? HACKER_PATHNAME_LIBC : HACKER_PATHNAME_LIBC_Q)

typedef size_t (*hacker_strlen_t)(const char* const);
static hacker_strlen_t hacker_orig_strlen = NULL;
static bytehook_stub_t hacker_stub_strlen = NULL;

typedef size_t (*hacker_strlen_chk_t)(const char *, size_t);
static hacker_strlen_chk_t hacker_orig_strlen_chk = NULL;
static bytehook_stub_t hacker_stub_strlen_chk = NULL;

static void hacker_bytehook_strlen_hooked(bytehook_stub_t task_stub, int status_code, const char *caller_path_name, const char *sym_name, void *new_func, void *prev_func, void *arg)
{
    if(BYTEHOOK_STATUS_CODE_ORIG_ADDR == status_code)
        hacker_orig_strlen = (hacker_strlen_t)prev_func;
    else
        LOG(">>>>> strlen() hooked. stub: %" PRIxPTR", status: %d, caller_path_name: %s, sym_name: %s, new_func: %" PRIxPTR", prev_func: %" PRIxPTR", arg: %" PRIxPTR,
            (uintptr_t)task_stub, status_code, caller_path_name, sym_name, (uintptr_t)new_func, (uintptr_t)prev_func, (uintptr_t)arg);
}

static void hacker_bytehook_strlen_chk_hooked(bytehook_stub_t task_stub, int status_code, const char *caller_path_name, const char *sym_name, void *new_func, void *prev_func, void *arg)
{
    if(BYTEHOOK_STATUS_CODE_ORIG_ADDR == status_code)
        hacker_orig_strlen_chk = (hacker_strlen_chk_t)prev_func;
    else
        LOG(">>>>> __strlen_chk() hooked. stub: %" PRIxPTR", status: %d, caller_path_name: %s, sym_name: %s, new_func: %" PRIxPTR", prev_func: %" PRIxPTR", arg: %" PRIxPTR,
            (uintptr_t)task_stub, status_code, caller_path_name, sym_name, (uintptr_t)new_func, (uintptr_t)prev_func, (uintptr_t)arg);
}

//static void hacker_bytehook_pre_dlopen(const char *filename, void *data)
//{
//    LOG("PRE dlopen(): %s, data: %p", filename, data);
//}
//
//static void hacker_bytehook_post_dlopen(const char *filename, int result, void *data)
//{
//    LOG("POST dlopen(): %s, result: %d, data: %p", filename, result, data);
//}

static size_t hacker_bytehook_strlen_automatic(const char* const s)
{
    BYTEHOOK_STACK_SCOPE();

    bool benchmark = (0 != strcmp(s, "bytehook manual test"));

    if(!benchmark) LOG("bytehook pre strlen");
    size_t ret = BYTEHOOK_CALL_PREV(hacker_bytehook_strlen_automatic, s);
    if(!benchmark) LOG("bytehook post strlen, ret=%zu", ret);

    return ret;
}

static size_t hacker_bytehook_strlen_chk_automatic(const char* s, size_t n)
{
    BYTEHOOK_STACK_SCOPE();

    bool benchmark = (0 != strcmp(s, "bytehook manual test"));

    if(!benchmark) LOG("bytehook pre __strlen_chk");
    size_t ret = BYTEHOOK_CALL_PREV(hacker_bytehook_strlen_chk_automatic, s, n);
    if(!benchmark) LOG("bytehook post __strlen_chk, ret=%zu", ret);

    return ret;
}

static size_t hacker_bytehook_strlen_manual(const char* const s)
{
    bool benchmark = (0 != strcmp(s, "bytehook manual test"));

    if(!benchmark) LOG("bytehook pre strlen");
    size_t ret = hacker_orig_strlen(s);
    if(!benchmark) LOG("bytehook post strlen, ret=%zu", ret);

    return ret;
}

static size_t hacker_bytehook_strlen_chk_manual(const char* s, size_t n)
{
    bool benchmark = (0 != strcmp(s, "bytehook manual test"));

    if(!benchmark) LOG("bytehook pre __strlen_chk");
    size_t ret = hacker_orig_strlen_chk(s, n);
    if(!benchmark) LOG("bytehook post __strlen_chk, ret=%zu", ret);

    return ret;
}

//static bool hacker_bytehook_strlen_allow_filter(const char *caller_path_name, void *arg)
//{
//    (void)arg;
//
//    // avoid deadlock in Android 11
//    if(NULL != strstr(caller_path_name, "libc.so")) return false;
//    if(NULL != strstr(caller_path_name, "libbase.so")) return false;
//    if(NULL != strstr(caller_path_name, "liblog.so")) return false;
//
//    return true;
//}

int hacker_bytehook_hook(void)
{
    //bytehook_add_dlopen_callback(hacker_bytehook_pre_dlopen, hacker_bytehook_post_dlopen, NULL);

    if(NULL != hacker_stub_strlen) return -1;

    void *hacker_bytehook_strlen = (BYTEHOOK_MODE_MANUAL == bytehook_get_mode() ? (void *)hacker_bytehook_strlen_manual : (void *)hacker_bytehook_strlen_automatic);
    void *hacker_bytehook_strlen_chk = (BYTEHOOK_MODE_MANUAL == bytehook_get_mode() ? (void *)hacker_bytehook_strlen_chk_manual : (void *)hacker_bytehook_strlen_chk_automatic);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    hacker_stub_strlen = bytehook_hook_single(
        "libsample.so",
        NULL,
        "strlen",
        hacker_bytehook_strlen,
        hacker_bytehook_strlen_hooked,
        NULL);
    hacker_stub_strlen_chk = bytehook_hook_single(
        "libsample.so",
        NULL,
        "__strlen_chk",
        hacker_bytehook_strlen_chk,
        hacker_bytehook_strlen_chk_hooked,
        NULL);

//    hacker_stub_strlen = bytehook_hook_partial(
//        hacker_bytehook_strlen_allow_filter,
//        NULL,
//        "libc.so",//NULL,
//        "strlen",
//        hacker_bytehook_strlen,
//        hacker_bytehook_strlen_hooked,
//        NULL);
//    hacker_stub_strlen_chk = bytehook_hook_partial(
//        hacker_bytehook_strlen_allow_filter,
//        NULL,
//        "libc.so",//NULL,
//        "__strlen_chk",
//        hacker_bytehook_strlen_chk,
//        hacker_bytehook_strlen_chk_hooked,
//        NULL);

    // this will cause deadlock in Android 11
    // need to ignore liblog.so and libbase.so, use bytehook_hook_partial() instead
//    hacker_stub_strlen = bytehook_hook_all(
//        NULL,
//        "strlen",
//        hacker_bytehook_strlen,
//        hacker_bytehook_strlen_hooked,
//        NULL);
//    hacker_stub_strlen_chk = bytehook_hook_all(
//        NULL,
//        "__strlen_chk",
//        hacker_bytehook_strlen_chk,
//        hacker_bytehook_strlen_chk_hooked,
//        NULL);

    gettimeofday(&end, NULL);
    LOG("bytehook hook cost: %" PRIu64 " us",
        (uint64_t)(end.tv_sec * 1000000 + end.tv_usec) - (uint64_t)(start.tv_sec * 1000000 + start.tv_usec));

    return 0;
}

int hacker_bytehook_unhook(void)
{
    if(NULL == hacker_stub_strlen && NULL == hacker_stub_strlen_chk) return -1;

    struct timeval start, end;
    gettimeofday(&start, NULL);

    if(NULL != hacker_stub_strlen)
    {
        bytehook_unhook(hacker_stub_strlen);
        hacker_stub_strlen = NULL;
    }
    if(NULL != hacker_stub_strlen_chk)
    {
        bytehook_unhook(hacker_stub_strlen_chk);
        hacker_stub_strlen_chk = NULL;
    }

    gettimeofday(&end, NULL);
    LOG("bytehook unhook cost: %" PRIu64 " us",
        (uint64_t)(end.tv_sec * 1000000 + end.tv_usec) - (uint64_t)(start.tv_sec * 1000000 + start.tv_usec));

    return 0;
}
