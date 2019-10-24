// RUN: %nvt -s 2 -- DynLoader %r/Oblivious/%basename.out

#include <cassert>
#include "NVT.h"
#include "Oblivious.h"

NVT_TEST_MODULE;

int idx;
int arr[256];
alignas(BLOCK_SIZE) int _arr[256];
int64_t arr64[256];
alignas(BLOCK_SIZE) int64_t _arr64[256];

extern "C" {

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  o_write_i32(arr, sizeof(arr), arr + idx, 42, false);
}

NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  o_write_i32(_arr, sizeof(_arr), _arr + idx, 42, true);
}

NVT_EXPORT void NVT_TEST_INIT(3)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(3)(void) {
  o_write_i64(arr64, sizeof(arr64), arr64 + idx, 42, false);
}

NVT_EXPORT void NVT_TEST_INIT(4)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(4)(void) {
  o_write_i64(_arr64, sizeof(_arr64), _arr64 + idx, 42, true);
}

int src_arr[4];

NVT_EXPORT void NVT_TEST_INIT(5)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0];
}

NVT_EXPORT void NVT_TEST_BEGIN(5)(void) {
  o_write(arr, sizeof(arr), arr + idx, false, src_arr, sizeof(src_arr), false);
}

NVT_EXPORT void NVT_TEST_INIT(6)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(6)(void) {
  o_write_T(arr, sizeof(arr), arr + idx, 42, false);
}

int perturb;

NVT_EXPORT void NVT_TEST_INIT(7)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0] % 4;
  perturb = (data[0] >> 2) % 12;
}

int src = 42;
alignas(64) int dst_arr[16];

NVT_EXPORT void NVT_TEST_BEGIN(7)(void) {
  o_write_T(dst_arr + perturb, 4 * sizeof(int), dst_arr + perturb + idx, src,
            false);
}

// oblivious write_list tests
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
  o_write_list_T(node1, larr + arr_select * idx, src, false);
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
  o_write_list_T(_node1, _larr + arr_select * idx, src, true);
}

// Test read optimizations for bigger data

NVT_EXPORT void NVT_TEST_INIT(10)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0];
}

NVT_EXPORT void NVT_TEST_BEGIN(10)(void) {
  o_write_T(arr64, sizeof(arr64), arr64 + idx, (int64_t)42, true, false);
}

NVT_EXPORT void NVT_TEST_INIT(11)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = data[0];
}

using T = typename std::aligned_storage<128, 4>::type;
T big_array[256];
T big_src;

NVT_EXPORT void NVT_TEST_BEGIN(11)(void) {
  o_write_T(big_array, sizeof(big_array), big_array + idx, big_src, true,
            false);
}
}
