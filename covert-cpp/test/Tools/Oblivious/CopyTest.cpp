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
void arr_print(T *arr, int sz) {
  *logd << "output: ";
  for (int i = 0; i < sz; ++i) {
    *logd << (int)(arr[i]) << ", ";
  }
  *logd << '\n';
};

int main() {
  logd = &std::cout;
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
    int16_t x, y = 56, z = 57;
    TEST(c = true; x = o_copy_i16(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 56
    // CHECK-NEXT: END TEST

    TEST(c = false; x = o_copy_i16(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 57
    // CHECK-NEXT: END TEST
  }

  {
    int32_t x, y = 56, z = 57;
    TEST(c = true; x = o_copy_i32(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 56
    // CHECK-NEXT: END TEST

    TEST(c = false; x = o_copy_i32(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 57
    // CHECK-NEXT: END TEST
  }

  {
    int64_t x, y = 56, z = 57;
    TEST(c = true; x = o_copy_i64(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 56
    // CHECK-NEXT: END TEST

    TEST(c = false; x = o_copy_i64(c, y, z); LOG((int)x);)  // CHECK: TEST
    // CHECK-NEXT: output: 57
    // CHECK-NEXT: END TEST
  }

  {
    int x[8];
    int y[8] = {0, 1, 2, 3, 4, 5, 6, 7}, z[8] = {8, 9, 10, 11, 12, 13, 14, 15};
    TEST(c = true; o_copy_i256((__m256i *)x, c, (const __m256i *)y, (const __m256i *)z, 0); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7
    // CHECK-NEXT: END TEST

    TEST(c = false; o_copy_i256((__m256i *)x, c, (const __m256i *)y, (const __m256i *)z, 0); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 8, 9, 10, 11, 12, 13, 14, 15
    // CHECK-NEXT: END TEST
  }

  {
    int x[16];
    int y[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    int z[16] = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    TEST(c = true; o_copy_arr<16>(x, c, y, z); arr_print(x, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    // CHECK-NEXT: END TEST

    TEST(c = false; o_copy_arr<16>(x, c, y, z); arr_print(x, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    // CHECK-NEXT: END TEST
  }

  {
    struct {
      int data[8];
    } x, y = {{0, 1, 2, 3, 4, 5, 6, 7}}, z = {{8, 9, 10, 11, 12, 13, 14, 15}};
    TEST(c = true; o_copy_T(x, c, y, z); arr_print(x.data, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 0, 1, 2, 3, 4, 5, 6, 7
    // CHECK-NEXT: END TEST

    TEST(c = false; o_copy_T(x, c, y, z); arr_print(x.data, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 8, 9, 10, 11, 12, 13, 14, 15
    // CHECK-NEXT: END TEST
  }

  { // test si256 bad alignment
    int i[9] = {0};
    int j[9] = {1 << 8, 0, 0, 0, 0, 0, 0, 0}, k[9] = {1 << 8, 0, 0, 0, 0, 0, 0, 0};
    int *x = (int *)(((char *)&i) + 1);
    int *y = (int *)(((char *)&j) + 1);
    int *z = (int *)(((char *)&k) + 1);
    TEST(c = true; o_copy_i256((__m256i *)x, c, (const __m256i *)y, (const __m256i *)z, 0); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 1, 0, 0, 0, 0, 0, 0, 0
    // CHECK-NEXT: END TEST

    TEST(c = false; o_copy_i256((__m256i *)x, c, (const __m256i *)y, (const __m256i *)z, 0); arr_print(x, 8);)  // CHECK: TEST
    // CHECK-NEXT: output: 1, 0, 0, 0, 0, 0, 0, 0
    // CHECK-NEXT: END TEST
  }

  {
    uint32_t x[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint32_t y[16] = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    uint32_t z[16] = {32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47};
    TEST(o_copy(x, true, y, z, 15 * sizeof(uint32_t)); arr_print(x, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 15,
    // CHECK-NEXT: END TEST
    TEST(o_copy(x, false, y, z, 15 * sizeof(uint32_t)); arr_print(x, 16);)  // CHECK: TEST
    // CHECK-NEXT: output: 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 15,
    // CHECK-NEXT: END TEST
  }

  {
    struct LongString {
      char val[2055];
    } x, y, z;
    TEST(c = true; o_copy(&x, c, &y, &z, sizeof(LongString));)  // CHECK: TEST
    // CHECK-NEXT: END TEST

    TEST(c = false; o_copy(&x, c, &y, &z, sizeof(LongString));)  // CHECK: TEST
    // CHECK-NEXT: END TEST
  }
}
