// Copyright (c) 2020-present, ByteDance, Inc.
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

// Created by Kelun Cai (caikelun@bytedance.com) on 2020-06-02.

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include "bytesig.h"

#define BYTESIG_DEBUG 0

#if BYTESIG_DEBUG
#include <android/log.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define BYTESIG_LOG(fmt, ...)  __android_log_print(ANDROID_LOG_INFO, "bytesig_tag", fmt, ##__VA_ARGS__)
#pragma clang diagnostic pop
#else
#define BYTESIG_LOG(fmt, ...)
#endif


//
// bionic's sigprocmask() / sigprocmask64() / sigaction() / sigaction64()
//

typedef int (*bytesig_libc_sigprocmask_t)(int how, const sigset_t *set, sigset_t *oldset);
typedef int (*bytesig_libc_sigprocmask64_t)(int how, const sigset64_t *set, sigset64_t *oldset);
typedef int (*bytesig_libc_sigaction64_t)(int, const struct sigaction64 *, struct sigaction64 *);
typedef int (*bytesig_libc_sigaction_t)(int, const struct sigaction *, struct sigaction *);
static bytesig_libc_sigprocmask64_t bytesig_libc_sigprocmask64 = NULL;
static bytesig_libc_sigprocmask_t bytesig_libc_sigprocmask = NULL;
static bytesig_libc_sigaction64_t bytesig_libc_sigaction64 = NULL;
static bytesig_libc_sigaction_t bytesig_libc_sigaction = NULL;

static int bytesig_load_symbol(void)
{
    static int loaded = -1; // -1: unload, 0: OK, 1: Failed

    if(loaded >= 0) return loaded;

    void *libc = dlopen("libc.so", RTLD_LOCAL);
    if(NULL != libc)
    {
        // sigprocmask64() / sigprocmask()
        bytesig_libc_sigprocmask64 = (bytesig_libc_sigprocmask64_t)dlsym(libc, "sigprocmask64");
        if(NULL == bytesig_libc_sigprocmask64)
            bytesig_libc_sigprocmask = (bytesig_libc_sigprocmask_t)dlsym(libc, "sigprocmask");

        // sigaction64() / sigaction()
        bytesig_libc_sigaction64 = (bytesig_libc_sigaction64_t)dlsym(libc, "sigaction64");
        if(NULL == bytesig_libc_sigaction64)
            bytesig_libc_sigaction = (bytesig_libc_sigaction_t)dlsym(libc, "sigaction");

        dlclose(libc);
    }

    loaded = (((NULL == bytesig_libc_sigprocmask64 && NULL == bytesig_libc_sigprocmask)
        || (NULL == bytesig_libc_sigaction64 && NULL == bytesig_libc_sigaction)) ? 1 : 0);
    return loaded;
}

static int bytesig_real_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    if(NULL != bytesig_libc_sigprocmask64)
    {
        // struct sigset_t -> struct sigset64_t
        sigset64_t set64;
        if(NULL != set)
        {
            memset(&set64, 0, sizeof(sigset64_t));
            memcpy(&set64, set, sizeof(sigset_t));
        }

        // call bionic's sigprocmask64()
        sigset64_t oldset64;
        int result = bytesig_libc_sigprocmask64(how, NULL != set ? &set64 : NULL, NULL != oldset ? &oldset64 : NULL);

        // struct sigset64_t -> struct sigset_t
        if(NULL != oldset)
        {
            memcpy(oldset, &oldset64, sizeof(sigset_t));
        }

        return result;
    }
    else
    {
        return bytesig_libc_sigprocmask(how, set, oldset);
    }
}

static int bytesig_real_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if(NULL != bytesig_libc_sigaction64)
    {
        // struct sigaction -> struct sigaction64
        struct sigaction64 act64;
        if(NULL != act)
        {
            memset(&act64, 0, sizeof(struct sigaction64));
            memcpy(&act64.sa_mask, &act->sa_mask, sizeof(sigset_t));
            act64.sa_flags = act->sa_flags;
            if((unsigned int)(act->sa_flags) & (unsigned int)SA_SIGINFO)
                act64.sa_sigaction = act->sa_sigaction;
            else
                act64.sa_handler = act->sa_handler;
        }

        // call bionic's sigaction64()
        struct sigaction64 oldact64;
        int result = bytesig_libc_sigaction64(signum, NULL != act ? &act64 : NULL, NULL != oldact ? &oldact64 : NULL);

        // struct sigaction64 -> struct sigaction
        if(NULL != oldact)
        {
            memset(oldact, 0, sizeof(struct sigaction));
            memcpy(&oldact->sa_mask, &oldact64.sa_mask, sizeof(sigset_t));
            oldact->sa_flags = oldact64.sa_flags;
            if((unsigned int)(oldact->sa_flags) & (unsigned int)SA_SIGINFO)
                oldact->sa_sigaction = oldact64.sa_sigaction;
            else
                oldact->sa_handler = oldact64.sa_handler;
        }

        return result;
    }
    else
    {
        // call bionic's sigaction()
        return bytesig_libc_sigaction(signum, act, oldact);
    }
}


//
// signal manager
//

#define BYTESIG_PROTECTED_THREADS_MAX 256

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct
{
    pid_t tid;
    sigjmp_buf *jbuf;
} bytesig_thread_info_t;
#pragma clang diagnostic pop

typedef struct
{
    struct sigaction prev_action;
    bytesig_thread_info_t protected_threads[BYTESIG_PROTECTED_THREADS_MAX];
} bytesig_signal_t;

// array index is signal number, corresponds to signals 1 to 31, except 9 and 19
static bytesig_signal_t *bytesig_signal_array[__SIGRTMIN];

static void bytesig_sigorset(sigset_t* dest, sigset_t* left, sigset_t* right)
{
    sigemptyset(dest);
    for(size_t i = 1; i < sizeof(sigset_t) * CHAR_BIT; i++)
    {
        if (sigismember(left, (int)i) == 1 || sigismember(right, (int)i) == 1)
            sigaddset(dest, (int)i);
    }
}

static void bytesig_handler(int signum, siginfo_t *siginfo, void *context)
{
    bytesig_signal_t *sig = bytesig_signal_array[signum];
    pid_t tid = gettid();
    if(0 == tid) tid = (pid_t)syscall(SYS_gettid);

    // check protect info & do siglongjmp
    for(size_t i = 0; i < BYTESIG_PROTECTED_THREADS_MAX; i++)
    {
        bytesig_thread_info_t *thdinfo = &(sig->protected_threads[i]);
        if(tid == __atomic_load_n(&(thdinfo->tid), __ATOMIC_RELAXED))
        {
            BYTESIG_LOG("siglongjmp signal %d (code %d) at %zu", signum, siginfo->si_code, i);

            unsigned int ret_signum = (((unsigned int)signum & 0xFFU) << 16U);
            unsigned int ret_code = 0U;
            if(siginfo->si_code > 0)
                ret_code = (((unsigned int)(siginfo->si_code) & 0xFFU) << 8U);
            else if(siginfo->si_code < 0)
                ret_code = (unsigned int)(-(siginfo->si_code)) & 0xFFU;
            int ret_val = (int)(ret_signum | ret_code);

            siglongjmp(*(__atomic_load_n(&(thdinfo->jbuf), __ATOMIC_RELAXED)), ret_val);
        }
    }

    // build signal mask for previous signal handler
    sigset_t prev_mask;
    bytesig_sigorset(&prev_mask, &(((ucontext_t *)context)->uc_sigmask), &(sig->prev_action.sa_mask));

    // fix the signal mask
    //
    // (1) add the current signal number if SA_NODEFER is not set
    if(0 == ((unsigned int)(sig->prev_action.sa_flags) & (unsigned int)SA_NODEFER))
        sigaddset(&prev_mask, signum);
    //
    // (2) these three signals should always be masked, We don't want to cause trouble
    sigaddset(&prev_mask, SIGPIPE);
    sigaddset(&prev_mask, SIGUSR1);
    sigaddset(&prev_mask, SIGQUIT);

    // set signal mask for previous signal handler
    bytesig_real_sigprocmask(SIG_SETMASK, &prev_mask, NULL);

    // call previous signal handler
    if((unsigned int)(sig->prev_action.sa_flags) & (unsigned int)SA_SIGINFO)
    {
        sig->prev_action.sa_sigaction(signum, siginfo, context);
    }
    else
    {
        if(SIG_DFL != sig->prev_action.sa_handler && SIG_IGN != sig->prev_action.sa_handler)
            sig->prev_action.sa_handler(signum);
    }
}

int bytesig_init(int signum)
{
    int ret = -1;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    if(signum <= 0 || signum >= __SIGRTMIN || signum == SIGKILL || signum == SIGSTOP) return -1;

    if(NULL != bytesig_signal_array[signum]) return -1;
    pthread_mutex_lock(&lock);
    if(NULL != bytesig_signal_array[signum]) goto end;

    // load symbols from bionic (only once)
    if(0 != bytesig_load_symbol()) goto end;

    bytesig_signal_t *sig = calloc(1, sizeof(bytesig_signal_t));
    if(NULL == sig) goto end;

    // register the signal with the kernel
    // in our handler, we start off with all signals blocked
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    sigfillset(&act.sa_mask);
    act.sa_sigaction = bytesig_handler;
    act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    if(0 != bytesig_real_sigaction(signum, &act, &sig->prev_action))
    {
        free(sig);
        goto end;
    }

    bytesig_signal_array[signum] = sig;
    ret = 0;

 end:
    pthread_mutex_unlock(&lock);
    return ret;
}

void bytesig_protect(pid_t tid, sigjmp_buf *jbuf, const int signums[], size_t signums_cnt)
{
    for(size_t i = 0; i < signums_cnt; i++)
    {
        int signum = signums[i];
        if(signum <= 0 || signum >= __SIGRTMIN || signum == SIGKILL || signum == SIGSTOP) continue;

        bytesig_signal_t *sig = bytesig_signal_array[signum];
        if(NULL == sig) continue;

        // check repeated thread
        bool repeated = false;
        for(size_t j = 0; j < BYTESIG_PROTECTED_THREADS_MAX; j++)
        {
            bytesig_thread_info_t *thdinfo = &sig->protected_threads[j];
            if(tid == thdinfo->tid)
            {
                repeated = true;
                break;
            }
        }
        if(repeated) continue;

        // save thread-ID and jump buffer
        size_t j = 0;
        while(1)
        {
            bytesig_thread_info_t *thdinfo = &sig->protected_threads[j];
            if(0 == thdinfo->tid)
            {
                pid_t expected = 0;
                if(__atomic_compare_exchange_n(&thdinfo->tid, &expected, tid, true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                {
                    thdinfo->jbuf = jbuf;
                    BYTESIG_LOG("protect_start signal %d at %zu", signum, j);
                    break; // finished
                }
            }

            j++;
            if(BYTESIG_PROTECTED_THREADS_MAX == j) j = 0;
        }
    }
}

void bytesig_unprotect(pid_t tid, const int signums[], size_t signums_cnt)
{
    for(size_t i = 0; i < signums_cnt; i++)
    {
        int signum = signums[i];
        if(signum <= 0 || signum >= __SIGRTMIN || signum == SIGKILL || signum == SIGSTOP) continue;

        bytesig_signal_t *sig = bytesig_signal_array[signum];
        if(NULL == sig) continue;

        // free thread-ID and jump buffer
        for(size_t j = 0; j < BYTESIG_PROTECTED_THREADS_MAX; j++)
        {
            bytesig_thread_info_t *thdinfo = &(sig->protected_threads[j]);
            if(tid == thdinfo->tid)
            {
                thdinfo->jbuf = NULL;
                __atomic_store_n(&thdinfo->tid, 0, __ATOMIC_RELEASE);
                BYTESIG_LOG("protect_end signal %d at %zu", signum, j);
                break; // finished
            }
        }
    }
}
