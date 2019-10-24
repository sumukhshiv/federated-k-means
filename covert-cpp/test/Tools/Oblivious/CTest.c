// RUN: %r/%basename.out | FileCheck %s
#include "../include/Test.h"
#include "Oblivious.h"

#include <stdbool.h>

// expected-no-diagnostics

#define LOG(val) fprintf(stdout, "output: %d\n", (val));

#define DECLARE_ARRAY(T, name, N) \
  T name[N]; \
  for (int i = 0; i < N; ++i) { \
    name[i] = i; \
  }

void arr_print(int *arr, int sz) {
  fprintf(stdout, "output: ");
  for (int i = 0; i < sz; ++i) {
    fprintf(stdout, "%d, ", arr[i]);
  }
  fprintf(stdout, "\n");
}

int main() {
  bool c;

  { // test double copy
    int w, x, y = 56, z = 57;
    TEST(w = o_copy_i32(false, y, z); x = o_copy_i32(true, y, z); LOG(w); LOG(x);)  // CHECK: TEST
    // CHECK-NEXT: output: 57
    // CHECK-NEXT: output: 56
    // CHECK-NEXT: END TEST
  }

  {
    int8_t x, y = 56, z = 57;
    TEST(c = true; x = o_copy_i8(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 56
    // CHECK-NEXT: END TEST

    TEST(c = false; x = o_copy_i8(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 57
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int, arr, 256);
    TEST(int x = o_read_i32(arr, sizeof(arr), arr + 200, false); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 200
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int32_t, arr, 256);
    int32_t x[5];
    TEST(o_read(x, sizeof(x), arr, sizeof(arr), arr + 137, true, false); LOG(x[2]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 139
    // CHECK-NEXT: END TEST
  }

  {
    int x[8];
    int y[8] = {0, 1, 2, 3, 4, 5, 6, 7}, z[8] = {8, 9, 10, 11, 12, 13, 14, 15};
    TEST(c = 1; o_copy_i256((__m256i *)x, c, (const __m256i *)y, (const __m256i *)z, 0); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7
    // CHECK-NEXT: END TEST

    TEST(c = false; o_copy_i256((__m256i *)x, c, (const __m256i *)y, (const __m256i *)z, 0); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 8, 9, 10, 11, 12, 13, 14, 15
    // CHECK-NEXT: END TEST
  }

  {
    int32_t x[8] = {50, 51, 52, 53, 54, 55, 56, 57};
    int32_t y[8] = {0, 1, 2, 3, 4, 5, 6, 7}, z[8] = {8, 9, 10, 11, 12, 13, 14, 15};
    TEST(c = 1; o_copy(x, c, y, z, 7 * sizeof(int32_t)); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 57
    // CHECK-NEXT: END TEST

    TEST(c = false; o_copy(x, c, y, z, 7 * sizeof(int32_t)); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 8, 9, 10, 11, 12, 13, 14, 57
    // CHECK-NEXT: END TEST
  }
}
