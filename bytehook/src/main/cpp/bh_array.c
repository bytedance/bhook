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

// Created by Kelun Cai (caikelun@bytedance.com) on 2024-09-24.

#include "bh_array.h"

#include <stdlib.h>
#include <string.h>

int bh_array_push(bh_array_t *self, uintptr_t value) {
  if (__predict_false(self->count >= self->cap)) {
    self->cap *= 2;
    uintptr_t *heap = NULL;
    if (self->data == self->stack) {
      heap = malloc(sizeof(uintptr_t) * self->cap);
      if (NULL == heap) return -1;
      memcpy(heap, self->stack, sizeof(self->stack));
    } else {
      heap = realloc(self->data, sizeof(uintptr_t) * self->cap);
      if (NULL == heap) {
        free(self->data);
        return -1;
      }
    }
    self->data = heap;
  }

  self->data[self->count] = value;
  self->count++;
  return 0;
}

void bh_array_free(bh_array_t *self) {
  if (__predict_false(self->data != self->stack)) free(self->data);
}
