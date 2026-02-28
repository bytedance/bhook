#include "sample.h"

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define SAMPLE_TAG "bytehook_tag"

#pragma clang optimize off
void sample_test_strlen(void) {
  __android_log_print(ANDROID_LOG_INFO, SAMPLE_TAG, "libsample.so pre strlen()");
  size_t len = strlen("bytehook manual test");
  __android_log_print(ANDROID_LOG_INFO, SAMPLE_TAG, "libsample.so post strlen(). return value: %zu", len);
}
#pragma clang optimize on
