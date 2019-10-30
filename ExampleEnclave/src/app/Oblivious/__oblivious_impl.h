//===---------- __oblivious_impl.h - DLL symbols for libOblivious ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OBLIVIOUS_IMPL_H__
#define __OBLIVIOUS_OBLIVIOUS_IMPL_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "ObliviousDefs.h"

#if defined _WIN32 || defined __CYGWIN__
#if defined(__GNUC__) || defined(__GNUG__)
#define EXPORT __attribute__((dllexport))
#else
#define EXPORT __declspec(dllexport)
#endif
#else
#if __GNUC__ >= 4
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif
#endif

struct o_mem_node;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
EXPORT int8_t __o_copy_i8(int cond, int8_t left, int8_t right);
EXPORT int16_t __o_copy_i16(int cond, int16_t left, int16_t right);
EXPORT int32_t __o_copy_i32(int cond, int32_t left, int32_t right);
EXPORT int64_t __o_copy_i64(int cond, int64_t left, int64_t right);
EXPORT void __o_swap_i8(int cond, int8_t *left, int8_t *right);
EXPORT void __o_swap_i16(int cond, int16_t *left, int16_t *right);
EXPORT void __o_swap_i32(int cond, int32_t *left, int32_t *right);
EXPORT void __o_swap_i64(int cond, int64_t *left, int64_t *right);
#endif
EXPORT void __o_read_i32(int32_t *dst, const void *src_base, size_t src_size,
                         const int32_t *addr);
EXPORT void __o_read_i64(int64_t *dst, const void *src_base, size_t src_size,
                         const int64_t *addr);
EXPORT void __o_read_list_i32(int32_t *dst, const struct o_mem_node *src_list,
                              const int32_t *addr, bool list_aligned);
EXPORT void __o_read_list_i64(int64_t *dst, const struct o_mem_node *src_list,
                              const int64_t *addr, bool list_aligned);
EXPORT void __o_read(void *dst, size_t bytes_to_read, const void *src_base,
                     size_t src_size, const void *addr,
                     bool addr_is_array_elem, bool base_aligned);
EXPORT void __o_read_list(void *dst, size_t bytes_to_read,
                          const struct o_mem_node *src_list, const void *addr,
                          bool addr_is_array_elem, bool list_aligned);
EXPORT void __o_write_i32(void *dst_base, size_t dst_size, int32_t *addr,
                          int32_t val);
EXPORT void __o_write_i64(void *dst_base, size_t dst_size, int64_t *addr,
                          int64_t val);
EXPORT void __o_write_list_i32(const struct o_mem_node *dst_list, int32_t *addr,
                               int32_t val, bool list_aligned);
EXPORT void __o_write_list_i64(const struct o_mem_node *dst_list, int64_t *addr,
                               int64_t val, bool list_aligned);
EXPORT void __o_write(void *dst_base, size_t dst_size, void *addr,
                      bool addr_is_array_elem, const void *src,
                      size_t bytes_to_write, bool base_aligned);
EXPORT void __o_write_list(const struct o_mem_node *dst_list, void *addr,
                           bool addr_is_array_elem, const void *src,
                           size_t bytes_to_write, bool list_aligned);

#ifdef __cplusplus
}
#endif

#endif
