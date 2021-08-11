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

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <android/api-level.h>
#include "bh_linker.h"
#include "bh_dl.h"
#include "bh_const.h"
#include "bh_util.h"
#include "bh_log.h"

bh_linker_dlopen_ext_t bh_linker_dlopen_ext = NULL;
bh_linker_do_dlopen_t bh_linker_do_dlopen = NULL;
bh_linker_get_error_buffer_t bh_linker_get_error_buffer = NULL;
bh_linker_bionic_format_dlerror_t bh_linker_bionic_format_dlerror = NULL;

static pthread_mutex_t *bh_linker_g_dl_mutex = NULL;

int bh_linker_init(void)
{
    int api_level = bh_util_get_api_level();
    if(__ANDROID_API_L__ != api_level && __ANDROID_API_L_MR1__ != api_level &&
       __ANDROID_API_N__ != api_level && __ANDROID_API_N_MR1__ != api_level) return 0;

    void *linker = bh_dl_open_linker();
    if(NULL == linker) goto err;

    // for Android 5.0, 5.1, 7.0, 7.1
    if(NULL == (bh_linker_g_dl_mutex = (pthread_mutex_t *)(bh_dl_dsym(linker, BH_CONST_SYM_G_DL_MUTEX)))) goto err;

    // for Android 7.0, 7.1
    if(__ANDROID_API_N__ == api_level || __ANDROID_API_N_MR1__ == api_level)
    {
        bh_linker_dlopen_ext = (bh_linker_dlopen_ext_t)(bh_dl_dsym(linker, BH_CONST_SYM_DLOPEN_EXT));
        if(NULL == bh_linker_dlopen_ext)
        {
            if(NULL == (bh_linker_do_dlopen = (bh_linker_do_dlopen_t)(bh_dl_dsym(linker, BH_CONST_SYM_DO_DLOPEN)))) goto err;
            bh_linker_get_error_buffer = (bh_linker_get_error_buffer_t)(bh_dl_dsym(linker, BH_CONST_SYM_LINKER_GET_ERROR_BUFFER));
            bh_linker_bionic_format_dlerror = (bh_linker_bionic_format_dlerror_t)(bh_dl_dsym(linker, BH_CONST_SYM_BIONIC_FORMAT_DLERROR));
        }
    }

    bh_dl_close(linker);
    return 0;

 err:
    if(NULL != linker) bh_dl_close(linker);
    bh_linker_do_dlopen = NULL;
    bh_linker_dlopen_ext = NULL;
    bh_linker_g_dl_mutex = NULL;
    bh_linker_get_error_buffer = NULL;
    bh_linker_bionic_format_dlerror = NULL;
    return -1;
}

void bh_linker_lock(void)
{
    if(NULL != bh_linker_g_dl_mutex) pthread_mutex_lock(bh_linker_g_dl_mutex);
}

void bh_linker_unlock(void)
{
    if(NULL != bh_linker_g_dl_mutex) pthread_mutex_unlock(bh_linker_g_dl_mutex);
}
