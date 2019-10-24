// RUN: %r/%basename.out | FileCheck %s
#include "../include/Test.h"
#include "Oblivious.h"

// expected-no-diagnostics

#define LOG(val) *logd << "output: " << (val) << '\n';

#define DECLARE_ARRAY(T, name, N) \
  T name[N]; \
  for (int i = 0; i < N; ++i) { \
    name[i] = i; \
  }

#define DECLARE_ALIGNED_ARRAY(T, name, N, align) \
  alignas(align) T name[N]; \
  for (int i = 0; i < N; ++i) { \
    name[i] = i; \
  }

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

  {
    DECLARE_ARRAY(int, arr, 256);
    TEST(for (int i = 0; i < 200; i += 3) {
           o_write_i32(arr, sizeof(arr), arr + i, -1, false);
         }
         for (int i = 128; i < 158; ++i) {
           LOG(arr[i]);
         });
    // CHECK: TEST
    // CHECK-NEXT: output: 128
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 130
    // CHECK-NEXT: output: 131
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 133
    // CHECK-NEXT: output: 134
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 136
    // CHECK-NEXT: output: 137
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 139
    // CHECK-NEXT: output: 140
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 142
    // CHECK-NEXT: output: 143
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 145
    // CHECK-NEXT: output: 146
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 148
    // CHECK-NEXT: output: 149
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 151
    // CHECK-NEXT: output: 152
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 154
    // CHECK-NEXT: output: 155
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 157
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int, arr, 12, BLOCK_SIZE);
    TEST(o_write_i32(arr, sizeof(arr), arr + 7, 42, true); LOG(arr[7]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int64_t, arr, 256);
    TEST(for (int i = 0; i < 200; i += 3) {
           o_write_i64(arr, sizeof(arr), arr + i, -1, false);
         }
         for (int i = 128; i < 158; ++i) {
           LOG(arr[i]);
         });
    // CHECK: TEST
    // CHECK-NEXT: output: 128
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 130
    // CHECK-NEXT: output: 131
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 133
    // CHECK-NEXT: output: 134
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 136
    // CHECK-NEXT: output: 137
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 139
    // CHECK-NEXT: output: 140
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 142
    // CHECK-NEXT: output: 143
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 145
    // CHECK-NEXT: output: 146
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 148
    // CHECK-NEXT: output: 149
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 151
    // CHECK-NEXT: output: 152
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 154
    // CHECK-NEXT: output: 155
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 157
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int64_t, arr, 12, BLOCK_SIZE);
    TEST(o_write_i64(arr, sizeof(arr), arr + 7, 42, true); LOG(arr[7]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int32_t, arr, 8);
    int32_t x[5] = {12, 13, 14, 15, 16};
    const size_t arr_sz = sizeof(arr) / sizeof(int32_t);
    TEST(o_write(arr, sizeof(arr), arr + 1, true, x, sizeof(x), false); arr_print(arr, arr_sz);)
    // CHECK: TEST
    // CHECK-NEXT: output: 0, 12, 13, 14, 15, 16, 6, 7
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int32_t, arr, 8, BLOCK_SIZE);
    int32_t x[5] = {12, 13, 14, 15, 16};
    const size_t arr_sz = sizeof(arr) / sizeof(int32_t);
    TEST(o_write(arr, sizeof(arr), arr + 1, true, x, sizeof(x), true); arr_print(arr, arr_sz);)
    // CHECK: TEST
    // CHECK-NEXT: output: 0, 12, 13, 14, 15, 16, 6, 7
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int, arr, 256);
    TEST(for (int i = 0; i < 200; i += 18) {
           int x = -1;
           o_write(arr, sizeof(arr), arr + i, true, &x, sizeof(x), false);
         }
         for (int i = 0; i < 200; i += 9) {
           LOG(arr[i]);
         });
    // CHECK: TEST
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 9
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 27
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 45
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 63
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 81
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 99
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 117
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 135
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 153
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 171
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: output: 189
    // CHECK-NEXT: output: -1
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int, arr, 256);
    TEST(o_write_T(arr, sizeof(arr), arr + 19, 42, false); LOG(arr[19]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int, arr, 256, BLOCK_SIZE);
    TEST(o_write_T(arr, sizeof(arr), arr + 19, 42, true); LOG(arr[19]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    struct S {
      S() = default;
      S(int _x) : x(_x) {}
      S(int _x, int _y, int _z) : x(_x), y(_y), z(_z) {}
      int x;
      int y;
      int z;
    };
    DECLARE_ARRAY(S, arr, 256);
    arr[19] = {3, 4, 5};
    S s{92, 93, 94};
    TEST(o_write_T(arr, sizeof(arr), arr + 19, s, false); LOG(s.x); LOG(s.y); LOG(s.z);)
    // CHECK: TEST
    // CHECK-NEXT: output: 92
    // CHECK-NEXT: output: 93
    // CHECK-NEXT: output: 94
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int, arr1, 256);
    DECLARE_ARRAY(int, arr2, 256);
    DECLARE_ARRAY(int, arr3, 256);
    DECLARE_ARRAY(int, arr4, 256);
    o_mem_node *node4 = new o_mem_node({nullptr, arr4, sizeof(arr4)});
    o_mem_node *node3 = new o_mem_node({node4, arr3, sizeof(arr3)});
    o_mem_node *node2 = new o_mem_node({node3, arr2, sizeof(arr2)});
    o_mem_node *node1 = new o_mem_node({node2, arr1, sizeof(arr1)});
    TEST(o_write_list_T(node1, arr1 + 19, 42, false); LOG(arr1[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
    TEST(o_write_list_T(node1, arr2 + 19, 42, false); LOG(arr2[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
    TEST(o_write_list_T(node1, arr3 + 19, 42, false); LOG(arr3[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
    TEST(o_write_list_T(node1, arr4 + 19, 42, false); LOG(arr4[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int, arr1, 256, BLOCK_SIZE);
    DECLARE_ALIGNED_ARRAY(int, arr2, 256, BLOCK_SIZE);
    DECLARE_ALIGNED_ARRAY(int, arr3, 256, BLOCK_SIZE);
    DECLARE_ALIGNED_ARRAY(int, arr4, 256, BLOCK_SIZE);
    o_mem_node *node4 = new o_mem_node({nullptr, arr4, sizeof(arr4)});
    o_mem_node *node3 = new o_mem_node({node4, arr3, sizeof(arr3)});
    o_mem_node *node2 = new o_mem_node({node3, arr2, sizeof(arr2)});
    o_mem_node *node1 = new o_mem_node({node2, arr1, sizeof(arr1)});
    TEST(o_write_list_T(node1, arr1 + 19, 42, true); LOG(arr1[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
    TEST(o_write_list_T(node1, arr2 + 19, 42, true); LOG(arr2[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
    TEST(o_write_list_T(node1, arr3 + 19, 42, true); LOG(arr3[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
    TEST(o_write_list_T(node1, arr4 + 19, 42, true); LOG(arr4[42]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  // Test optimizations
  { // optimize 64-bit write
    DECLARE_ARRAY(int64_t, arr, 256);
    int64_t val = 42;
    TEST(o_write(arr, sizeof(arr), arr + 19, true, &val, sizeof(val), false); LOG(arr[19]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }

  { // optimize 64-byte+ read
    struct T {
      T() = default;
      T(int x) : data{} {
        data[17] = x;
      }
      int data[32];
    };
    DECLARE_ARRAY(T, arr, 256);
    T val(42);
    TEST(o_write_T(arr, sizeof(arr), arr + 19, val, true, false); LOG(arr[19].data[17]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: END TEST
  }
}
