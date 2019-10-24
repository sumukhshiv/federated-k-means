// RUN: %nvt -s 2 -- DynLoader %r/Oblivious/%basename.out

#include "NVT.h"
#include "Oblivious.h"
#include "oarray.h"

#undef NDEBUG
#include <cassert>
#define NDEBUG

NVT_TEST_MODULE;

using namespace oblivious;

int idx;
int arr[256];
oarray<int, 256> _arr;
int64_t arr64[256];
oarray<int64_t, 256> _arr64;
int res;

extern "C" {

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  res = o_read_i32(arr, sizeof(arr), arr + idx, false);
}

NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  res = o_read_i32(_arr.data(), sizeof(_arr), _arr.data() + idx, true);
}

NVT_EXPORT void NVT_TEST_INIT(3)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(3)(void) {
  res = o_read_i64(arr64, sizeof(arr64), arr64 + idx, false);
}

NVT_EXPORT void NVT_TEST_INIT(4)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(4)(void) {
  res = o_read_i64(_arr64.data(), sizeof(_arr64), _arr64.data() + idx, true);
}

int res_arr[4];

NVT_EXPORT void NVT_TEST_INIT(5)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0];
}

NVT_EXPORT void NVT_TEST_BEGIN(5)(void) {
  o_read(res_arr, sizeof(res_arr), arr, sizeof(arr), arr + idx, false, false);
}

NVT_EXPORT void NVT_TEST_INIT(6)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

struct S {
  int x;
  int y;
  int z;
} sret, sarr[256];

NVT_EXPORT void NVT_TEST_BEGIN(6)(void) {
  sret = o_read_T(sarr, sizeof(sarr), sarr + idx, false);
}

int perturb;

NVT_EXPORT void NVT_TEST_INIT(7)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0] % 4;
  perturb = (data[0] >> 2) % 12;
}

int dst;
alignas(64) int src_arr[16];

NVT_EXPORT void NVT_TEST_BEGIN(7)(void) {
  dst = o_read_T(src_arr, 4 * sizeof(int), src_arr + perturb + idx, false);
}

// oblivious read_list tests
unsigned char arr_select;
int larr[1024];
o_mem_node *node4 =
    new o_mem_node({nullptr, larr + 3 * 256, 256 * sizeof(int)});
o_mem_node *node3 = new o_mem_node({node4, larr + 2 * 256, 256 * sizeof(int)});
o_mem_node *node2 = new o_mem_node({node3, larr + 1 * 256, 256 * sizeof(int)});
o_mem_node *node1 = new o_mem_node({node2, larr + 0 * 256, 256 * sizeof(int)});

NVT_EXPORT void NVT_TEST_INIT(8)(unsigned char *data, unsigned size) {
  assert(size >= 2);
  idx = data[0];
  arr_select = data[1] % 4;
}

NVT_EXPORT void NVT_TEST_BEGIN(8)(void) {
  dst = o_read_list_T(node1, larr + arr_select * idx, false);
}

alignas(BLOCK_SIZE) int _larr[1024];
o_mem_node *_node4 =
    new o_mem_node({nullptr, _larr + 3 * 256, 256 * sizeof(int)});
o_mem_node *_node3 =
    new o_mem_node({_node4, _larr + 2 * 256, 256 * sizeof(int)});
o_mem_node *_node2 =
    new o_mem_node({_node3, _larr + 1 * 256, 256 * sizeof(int)});
o_mem_node *_node1 =
    new o_mem_node({_node2, _larr + 0 * 256, 256 * sizeof(int)});

NVT_EXPORT void NVT_TEST_INIT(9)(unsigned char *data, unsigned size) {
  assert(size >= 2);
  idx = data[0];
  arr_select = data[1] % 4;
}

NVT_EXPORT void NVT_TEST_BEGIN(9)(void) {
  dst = o_read_list_T(_node1, _larr + arr_select * idx, true);
}

// Test read optimizations for bigger data

NVT_EXPORT void NVT_TEST_INIT(10)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0];
}

NVT_EXPORT void NVT_TEST_BEGIN(10)(void) {
  dst = o_read_T(arr64, sizeof(arr64), arr64 + idx, true, false);
}

NVT_EXPORT void NVT_TEST_INIT(11)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0];
}

using T = typename std::aligned_storage<128, 4>::type;
T big_array[256];
T big_dst;

NVT_EXPORT void NVT_TEST_BEGIN(11)(void) {
  big_dst =
      o_read_T(big_array, sizeof(big_array), big_array + idx, true, false);
}
}
