// RUN: %r/%basename.out | FileCheck %s
#include "../include/Test.h"
#include "Oblivious.h"

// expected-no-diagnostics

struct I2 {
  int x;
  int y;
  int z;
};

#define LOG(val) *logd << "output: " << (val) << '\n';

template <typename T>
void arr_print(const T *arr, int sz) {
  *logd << "output: ";
  for (int i = 0; i < sz; ++i) {
    *logd << (int)(arr[i]) << ", ";
  }
  *logd << '\n';
};

int main() {
  logd = &std::cout;

  {
    int8_t x = 42, y = 43, *w = &x, *z = &y;
    TEST(o_swap_i8(true, w, z); o_swap_i8(true, w, z); LOG((int)x); LOG((int)y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i8(false, w, z); LOG((int)x); LOG((int)y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i8(true, w, z); LOG((int)x); LOG((int)y);)  // CHECK: TEST
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    int16_t x = 42, y = 43, *w = &x, *z = &y;
    TEST(o_swap_i16(true, w, z); o_swap_i16(true, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i16(false, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i16(true, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    int32_t x = 42, y = 43, *w = &x, *z = &y;
    TEST(o_swap_i32(true, w, z); o_swap_i32(true, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i32(false, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i32(true, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    int64_t x = 42, y = 43, *w = &x, *z = &y;
    TEST(o_swap_i64(true, w, z); o_swap_i64(true, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i64(false, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: END TEST
    TEST(o_swap_i64(true, w, z); LOG(x); LOG(y);)  // CHECK: TEST
    // CHECK-NEXT: output: 43
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    int64_t x[] = {0, 1, 2, 3};
    int64_t y[] = {8, 9, 10, 11};
    TEST(o_swap_i256(true, (__m256i *)x, (__m256i *)y); o_swap_i256(true, (__m256i *)x, (__m256i *)y); arr_print(x, 4); arr_print(y, 4);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3
    // CHECK-NEXT: output: 8, 9, 10, 11
    // CHECK-NEXT: END TEST
    TEST(o_swap_i256(false, (__m256i *)x, (__m256i *)y); arr_print(x, 4); arr_print(y, 4);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3
    // CHECK-NEXT: output: 8, 9, 10, 11
    // CHECK-NEXT: END TEST
    TEST(o_swap_i256(true, (__m256i *)x, (__m256i *)y); arr_print(x, 4); arr_print(y, 4);)  // CHECK: TEST
    // CHECK-NEXT: output: 8, 9, 10, 11
    // CHECK-NEXT: output: 0, 1, 2, 3
    // CHECK-NEXT: END TEST
  }

  {
    uint32_t x[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint32_t y[16] = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    TEST(o_swap(false, x, y, 15 * sizeof(uint32_t)); arr_print(x, 16); arr_print(y, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    // CHECK-NEXT: output: 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    // CHECK-NEXT: END TEST

    TEST(o_swap(true, x, y, 15 * sizeof(uint32_t)); arr_print(x, 16); arr_print(y, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 15,
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 31,
    // CHECK-NEXT: END TEST
  }

  {
    int x[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    int y[16] = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    TEST(o_swap_arr<15>(false, x, y); arr_print(x, 16); arr_print(y, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    // CHECK-NEXT: output: 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    // CHECK-NEXT: END TEST

    TEST(o_swap_arr<15>(true, x, y); arr_print(x, 16); arr_print(y, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 15,
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 31,
    // CHECK-NEXT: END TEST
  }

  {
    struct {
      int data[8];
    } x = {{0, 1, 2, 3, 4, 5, 6, 7}}, y = {{8, 9, 10, 11, 12, 13, 14, 15}};
    TEST(o_swap_T(false, x, y); arr_print(x.data, 8); arr_print(y.data, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7
    // CHECK-NEXT: output: 8, 9, 10, 11, 12, 13, 14, 15
    // CHECK-NEXT: END TEST

    TEST(o_swap_T(true, x, y); arr_print(x.data, 8); arr_print(y.data, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 8, 9, 10, 11, 12, 13, 14, 15
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7
    // CHECK-NEXT: END TEST
  }

}
