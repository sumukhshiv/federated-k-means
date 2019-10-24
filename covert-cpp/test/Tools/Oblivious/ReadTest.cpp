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
    DECLARE_ARRAY(int, arr, 272);
    TEST(for (int i = 0; i < 272; i += 29) {
           int x = o_read_i32(arr, sizeof(arr), arr + i, false); LOG(x);
         }; LOG(o_read_i32(arr, sizeof(arr), arr + 271, false));)
    // CHECK: TEST
    // CHECK-NEXT: output: 0
    // CHECK-NEXT: output: 29
    // CHECK-NEXT: output: 58
    // CHECK-NEXT: output: 87
    // CHECK-NEXT: output: 116
    // CHECK-NEXT: output: 145
    // CHECK-NEXT: output: 174
    // CHECK-NEXT: output: 203
    // CHECK-NEXT: output: 232
    // CHECK-NEXT: output: 261
    // CHECK-NEXT: output: 271
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int, arr, 12, BLOCK_SIZE);
    TEST(int x = o_read_i32(arr, sizeof(arr), arr + 7, true); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 7
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int64_t, arr, 64);
    TEST(for (int i = 0; i < 64; i += 7) {
           int64_t x = o_read_i64(arr, sizeof(arr), arr + i, false); LOG((int64_t)x);
         })
    // CHECK: TEST
    // CHECK-NEXT: output: 0
    // CHECK-NEXT: output: 7
    // CHECK-NEXT: output: 14
    // CHECK-NEXT: output: 21
    // CHECK-NEXT: output: 28
    // CHECK-NEXT: output: 35
    // CHECK-NEXT: output: 42
    // CHECK-NEXT: output: 49
    // CHECK-NEXT: output: 56
    // CHECK-NEXT: output: 63
    // CHECK-NEXT: END TEST
  }

  {
    struct T {
      int data[16];
      void operator=(int x) { data[0] = x; }
    };
    DECLARE_ARRAY(T, arr, 64);
    TEST(T x = o_read_T(arr, sizeof(arr), arr + 37, true, false); LOG(x.data[0]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 37
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int64_t, arr, 12, BLOCK_SIZE);
    TEST(int64_t x = o_read_i64(arr, sizeof(arr), arr + 7, true); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 7
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int32_t, arr, 256);
    int32_t x[5];
    const int sz = sizeof(x);
    TEST(o_read(x, sz, arr, sizeof(arr), arr + 137, true, false); arr_print(x, 5);)
    // CHECK: TEST
    // CHECK-NEXT: output: 137, 138, 139, 140, 141
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int32_t, arr, 256, 64);
    int32_t x[5];
    const int sz = sizeof(x);
    TEST(o_read(x, sz, arr, sizeof(arr), arr + 137, true, true); arr_print(x, 5);)
    // CHECK: TEST
    // CHECK-NEXT: output: 137, 138, 139, 140, 141
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ARRAY(int, arr, 256);
    TEST(int x = o_read_T(arr, sizeof(arr), arr + 19, true, false); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
  }

  {
    DECLARE_ALIGNED_ARRAY(int, arr, 256, BLOCK_SIZE);
    TEST(int x = o_read_T(arr, sizeof(arr), arr + 19, true, true); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
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
    TEST(S s = o_read_T(arr, sizeof(arr), arr + 19, true, false); LOG(s.x); LOG(s.y); LOG(s.z);)
    // CHECK: TEST
    // CHECK-NEXT: output: 3
    // CHECK-NEXT: output: 4
    // CHECK-NEXT: output: 5
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
    TEST(int x = o_read_list_T(node1, arr1 + 19, true, false); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
    TEST(int x = o_read_list_T(node1, arr2 + 19, true, false); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
    TEST(int x = o_read_list_T(node1, arr3 + 19, true, false); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
    TEST(int x = o_read_list_T(node1, arr4 + 19, true, false); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
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
    TEST(int x = o_read_list_T(node1, arr1 + 19, true, true); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
    TEST(int x = o_read_list_T(node1, arr2 + 19, true, true); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
    TEST(int x = o_read_list_T(node1, arr3 + 19, true, true); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
    TEST(int x = o_read_list_T(node1, arr4 + 19, true, true); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
  }

  // Test optimizations
  { // optimize 64-bit read
    DECLARE_ARRAY(int64_t, arr, 256);
    TEST(int64_t x = o_read_T(arr, sizeof(arr), arr + 19, true, false); LOG(x);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
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
    TEST(T x = o_read_T(arr, sizeof(arr), arr + 19, true, false); LOG(x.data[17]);)
    // CHECK: TEST
    // CHECK-NEXT: output: 19
    // CHECK-NEXT: END TEST
  }
}
