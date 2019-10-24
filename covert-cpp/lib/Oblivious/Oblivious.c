//===-------- Oblivious.c - libOblivious primitives implementation --------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "__oblivious_impl.h"
#include "Oblivious.h"
#include <assert.h>

#ifdef _MSC_VER
#pragma warning(disable : 4700)
#endif

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define IS_32_BIT_ALIGNED(addr) ((uintptr_t)addr % sizeof(int32_t) == 0)
#define IS_64_BIT_ALIGNED(addr) ((uintptr_t)addr % sizeof(int64_t) == 0)
#define IS_BLOCK_ALIGNED(addr) ((uintptr_t)addr % BLOCK_SIZE == 0)

extern inline int32_t o_read_i32(const void *src_base, size_t src_size,
                                 const int32_t *addr, bool base_aligned);
extern inline int64_t o_read_i64(const void *src_base, size_t src_size,
                                 const int64_t *addr, bool base_aligned);
extern inline int32_t o_read_list_i32(const struct o_mem_node *src_list,
                                      const int32_t *addr, bool list_aligned);
extern inline int64_t o_read_list_i64(const struct o_mem_node *src_list,
                                      const int64_t *addr, bool list_aligned);
extern inline void o_read(void *dst, size_t bytes_to_read, const void *src_base,
                          size_t src_size, const void *addr,
                          bool addr_is_array_elem, bool base_aligned);
extern inline void o_read_list(void *dst, size_t bytes_to_read,
                               const struct o_mem_node *src_list,
                               const void *addr, bool addr_is_array_elem,
                               bool list_aligned);
extern inline void o_write_i32(void *dst_base, size_t dst_size, int32_t *addr,
                               int32_t val, bool base_aligned);
extern inline void o_write_i64(void *dst_base, size_t dst_size, int64_t *addr,
                               int64_t val, bool base_aligned);
extern inline void o_write_list_i32(const struct o_mem_node *dst_list,
                                    int32_t *addr, int32_t val,
                                    bool list_aligned);
extern inline void o_write_list_i64(const struct o_mem_node *dst_list,
                                    int64_t *addr, int64_t val,
                                    bool list_aligned);
extern inline void o_write(void *dst_base, size_t dst_size, void *addr,
                           bool addr_is_array_elem, const void *src,
                           size_t bytes_to_write, bool list_aligned);
extern inline void o_write_list(const struct o_mem_node *dst_list, void *addr,
                                bool addr_is_array_elem, const void *src,
                                size_t bytes_to_write, bool list_aligned);

void o_copy(void *dst, int cond, const void *left, const void *right,
            size_t n) {
  size_t i = 0;
  int8_t *d = dst;
  const int8_t *l = left, *r = right;

  {
    typedef __m256i _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    for (; i + bytes_per_t <= n; i += bytes_per_t) {
      o_copy_i256((__m256i *)d, cond, (const _t *)l, (const _t *)r,
                  i / bytes_per_t);
    }
  }

  {
    typedef int64_t _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    for (; i + bytes_per_t <= n; i += bytes_per_t) {
      const size_t _i = i / bytes_per_t;
      ((_t *)d)[_i] =
          o_copy_i64(cond, ((const _t *)l)[_i], ((const _t *)r)[_i]);
    }
  }

  if (i < n) {
    typedef int _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    const size_t _i = i / bytes_per_t;
    ((_t *)d)[_i] = o_copy_i32(cond, ((const _t *)l)[_i], ((const _t *)r)[_i]);
    i += bytes_per_t;
  }

  {
    typedef int8_t _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    for (; i + bytes_per_t <= n; i += bytes_per_t) {
      d[i] = o_copy_i8(cond, l[i], r[i]);
    }
  }
}

void o_swap(int cond, void *left, void *right, size_t n) {
  size_t i = 0;
  int8_t *l = left, *r = right;

  {
    typedef __m256i _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    for (; i + bytes_per_t <= n; i += bytes_per_t) {
      o_swap_i256(cond, (_t *)(l + i), (_t *)(r + i));
    }
  }

  {
    typedef int64_t _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    for (; i + bytes_per_t <= n; i += bytes_per_t) {
      o_swap_i64(cond, (_t *)(l + i), (_t *)(r + i));
    }
  }

  if (i < n) {
    typedef int _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    o_swap_i32(cond, (_t *)(l + i), (_t *)(r + i));
    i += bytes_per_t;
  }

  {
    typedef int8_t _t;
    const size_t bytes_per_t = sizeof(_t) / sizeof(int8_t);
    for (; i + bytes_per_t <= n; i += bytes_per_t) {
      o_swap_i8(cond, l + i, r + i);
    }
  }
}

static inline uint32_t _mm256_extract_epi32_var(__m256i vec, int i) {
  __m128i indx = _mm_cvtsi32_si128(i);
  __m256i val = _mm256_permutevar8x32_epi32(vec, _mm256_castsi128_si256(indx));
  return _mm_cvtsi128_si32(_mm256_castsi256_si128(val));
}

static inline uint64_t _mm256_extract_epi64_var(__m256i vec, int i) {
  int64_t _i = ((int64_t)((i << 1) + 1) << 32) | ((int64_t)(i << 1));
  __m128i indx = _mm_cvtsi64_si128(_i);
  __m256i val = _mm256_permutevar8x32_epi32(vec, _mm256_castsi128_si256(indx));
  return _mm_cvtsi128_si64(_mm256_castsi256_si128(val));
}

void __o_read_i32(int32_t *dst, const void *src_base, size_t src_size,
                  const int32_t *addr) {
  bool found_addr = false;
  int32_t retval;
  assert(IS_32_BIT_ALIGNED(addr));
  assert(IS_BLOCK_ALIGNED(src_base));

  // initialize the index vector
  const int chunk_offset =
      (int)((uintptr_t)addr - (uintptr_t)src_base) % CHUNK_SIZE_I32;
  const int block_offset = chunk_offset % BLOCK_SIZE;
  int64_t remaining_bytes = src_size;
  const uint8_t *chunk = src_base;

#ifdef __LIBOBLIVIOUS_USE_VPGATHER__
  __m256i vindex = _mm256_set_epi32(
      (7 * BLOCK_SIZE) + block_offset, (6 * BLOCK_SIZE) + block_offset,
      (5 * BLOCK_SIZE) + block_offset, (4 * BLOCK_SIZE) + block_offset,
      (3 * BLOCK_SIZE) + block_offset, (2 * BLOCK_SIZE) + block_offset,
      (1 * BLOCK_SIZE) + block_offset, (0 * BLOCK_SIZE) + block_offset);

  for (; remaining_bytes >= CHUNK_SIZE_I32;
       chunk += CHUNK_SIZE_I32, remaining_bytes -= CHUNK_SIZE_I32) {
    // gather the values from the region of memory of size `CHUNK_SIZE_I32`
    const __m256i values =
        _mm256_i32gather_epi32((const int *)chunk, vindex, 1);

    // extract the value at the desired index in the 256-bit vector
    int32_t value = _mm256_extract_epi32_var(values, chunk_offset / BLOCK_SIZE);
    int should_capture = chunk + chunk_offset == (void *)addr;
    found_addr |= should_capture;
    retval = o_copy_i32(should_capture, value, retval);
  }
#endif

  const uint8_t *block = chunk;
  while (remaining_bytes > 0) {
    // The remaining bytes are fewer than the chunk size, so don't read
    // beyond the end of permissible memory!
    int should_capture = block + block_offset == (void *)addr;
    found_addr |= should_capture;
    retval =
        o_copy_i32(should_capture, *(int32_t *)(block + block_offset), retval);
    block += BLOCK_SIZE;
    remaining_bytes -= BLOCK_SIZE;
  }

  *dst = o_copy_i32(found_addr, retval, *dst);
}

void __o_read_i64(int64_t *dst, const void *src_base, size_t src_size,
                  const int64_t *addr) {
  bool found_addr = false;
  int64_t retval;
  assert(IS_64_BIT_ALIGNED(addr));
  assert(IS_BLOCK_ALIGNED(src_base));

  // initialize the index vector
  const int chunk_offset =
      (int)((uintptr_t)addr - (uintptr_t)src_base) % CHUNK_SIZE_I64;
  const int block_offset = chunk_offset % BLOCK_SIZE;
  int64_t remaining_bytes = src_size;
  const uint8_t *chunk = src_base;

#ifdef __LIBOBLIVIOUS_USE_VPGATHER__
  __m256i vindex = _mm256_set_epi64x(
      (3 * BLOCK_SIZE) + block_offset, (2 * BLOCK_SIZE) + block_offset,
      (1 * BLOCK_SIZE) + block_offset, (0 * BLOCK_SIZE) + block_offset);

  for (; remaining_bytes >= CHUNK_SIZE_I64;
       chunk += CHUNK_SIZE_I64, remaining_bytes -= CHUNK_SIZE_I64) {
    // gather the values from the region of memory of size `CHUNK_SIZE_I64`
    const __m256i values =
        _mm256_i64gather_epi64((const long long int *)chunk, vindex, 1);

    // extract the value at the desired index in the 256-bit vector
    int64_t value = _mm256_extract_epi64_var(values, chunk_offset / BLOCK_SIZE);
    int should_capture = chunk + chunk_offset == (void *)addr;
    found_addr |= should_capture;
    retval = o_copy_i64(should_capture, value, retval);
  }
#endif

  const uint8_t *block = chunk;
  while (remaining_bytes > 0) {
    // The remaining bytes are fewer than the chunk size, so don't read
    // beyond the end of permissible memory!
    int should_capture = block + block_offset == (void *)addr;
    found_addr |= should_capture;
    retval =
        o_copy_i64(should_capture, *(int64_t *)(block + block_offset), retval);
    block += BLOCK_SIZE;
    remaining_bytes -= BLOCK_SIZE;
  }

  *dst = o_copy_i64(found_addr, retval, *dst);
}

void __o_read_list_i32(int32_t *dst, const struct o_mem_node *src_list,
                       const int32_t *addr, bool list_aligned) {
  for (const struct o_mem_node *I = src_list, *const E = NULL; I != E;
       I = I->next) {
    const int32_t *src_base = I->base_addr;
    size_t src_size = I->size;
    if (!list_aligned) {
      ALIGN_TO_MASK(src_base, src_size, BLOCK_MASK);
    }
    __o_read_i32(dst, src_base, src_size, addr);
  }
}

void __o_read_list_i64(int64_t *dst, const struct o_mem_node *src_list,
                       const int64_t *addr, bool list_aligned) {
  for (const struct o_mem_node *I = src_list, *const E = NULL; I != E;
       I = I->next) {
    const int64_t *src_base = I->base_addr;
    size_t src_size = I->size;
    if (!list_aligned) {
      ALIGN_TO_MASK(src_base, src_size, BLOCK_MASK);
    }
    __o_read_i64(dst, src_base, src_size, addr);
  }
}

void __o_read(void *dst, size_t bytes_to_read, const void *src_base,
              size_t src_size, const void *addr, bool addr_is_array_elem,
              bool base_aligned) {
  if (addr_is_array_elem && bytes_to_read >= BLOCK_SIZE) {
    const uint8_t *_src_base = src_base;
    for (size_t i = 0; i < src_size; i += bytes_to_read) {
      o_copy(dst, _src_base + i == addr, _src_base + i, dst, bytes_to_read);
    }
  } else if (addr_is_array_elem && IS_64_BIT_ALIGNED(src_base) &&
             bytes_to_read % sizeof(int64_t) == 0) {
    if (!base_aligned) {
      ALIGN_TO_MASK(src_base, src_size, BLOCK_MASK);
    }
    int64_t *_dst = dst;
    const int64_t *_addr = addr;
    for (size_t j = 0; j < bytes_to_read / sizeof(int64_t); ++j) {
      __o_read_i64(_dst + j, src_base, src_size, _addr + j);
    }
  } else {
    if (!base_aligned) {
      ALIGN_TO_MASK(src_base, src_size, BLOCK_MASK);
    }
    int32_t *_dst = dst;
    const int32_t *_addr = addr;
    for (size_t j = 0; j < bytes_to_read / sizeof(int32_t); ++j) {
      __o_read_i32(_dst + j, src_base, src_size, _addr + j);
    }
  }
}

void __o_read_list(void *dst, size_t bytes_to_read,
                   const struct o_mem_node *src_list, const void *addr,
                   bool addr_is_array_elem, bool list_aligned) {
  for (const struct o_mem_node *I = src_list, *const E = NULL; I != E;
       I = I->next) {
    const void *src_base = I->base_addr;
    size_t src_size = I->size;
    __o_read(dst, bytes_to_read, src_base, src_size, addr, addr_is_array_elem,
             list_aligned);
  }
}

void __o_write_i32(void *dst_base, size_t dst_size, int32_t *addr,
                   int32_t val) {
  assert(IS_32_BIT_ALIGNED(addr));
  assert(IS_BLOCK_ALIGNED(dst_base));

  const int chunk_offset =
      (int)((uintptr_t)addr - (uintptr_t)dst_base) % CHUNK_SIZE_I32;
  const int block_offset = chunk_offset % BLOCK_SIZE;
  int64_t remaining_bytes = dst_size;
  const uint8_t *chunk = dst_base;

#ifdef __LIBOBLIVIOUS_USE_VPGATHER__
  __m256i vindex = _mm256_set_epi32(
      (7 * BLOCK_SIZE) + block_offset, (6 * BLOCK_SIZE) + block_offset,
      (5 * BLOCK_SIZE) + block_offset, (4 * BLOCK_SIZE) + block_offset,
      (3 * BLOCK_SIZE) + block_offset, (2 * BLOCK_SIZE) + block_offset,
      (1 * BLOCK_SIZE) + block_offset, (0 * BLOCK_SIZE) + block_offset);

  for (; remaining_bytes >= CHUNK_SIZE_I32;
       chunk += CHUNK_SIZE_I32, remaining_bytes -= CHUNK_SIZE_I32) {
    int32_t *_chunk = (int32_t *)chunk;
    // gather the values from the region of memory of size `CHUNK_SIZE_I32`
    const __m256i read_values =
        _mm256_i32gather_epi32((const int *)chunk, vindex, 1);

    // rewrite all values, only capturing the desired value once
#define COPY_VALUE_AT_INDEX_32(index)                                          \
  {                                                                            \
    const int32_t read_value = _mm256_extract_epi32(read_values, index);       \
    const size_t chunk_offset =                                                \
        (index * BLOCK_SIZE + block_offset) / sizeof(int32_t);                 \
    _chunk[chunk_offset] =                                                     \
        o_copy_i32(_chunk + chunk_offset == addr, val, read_value);            \
  }
    COPY_VALUE_AT_INDEX_32(0);
    COPY_VALUE_AT_INDEX_32(1);
    COPY_VALUE_AT_INDEX_32(2);
    COPY_VALUE_AT_INDEX_32(3);
    COPY_VALUE_AT_INDEX_32(4);
    COPY_VALUE_AT_INDEX_32(5);
    COPY_VALUE_AT_INDEX_32(6);
    COPY_VALUE_AT_INDEX_32(7);
  }
#endif

  const uint8_t *block = chunk;
  while (remaining_bytes > 0) {
    // The remaining bytes are fewer than the chunk size, so don't read/write
    // beyond the end of permissible memory!
    int32_t *_dst = (int32_t *)(block + block_offset);
    *_dst = o_copy_i32(_dst == addr, val, *_dst);
    block += BLOCK_SIZE;
    remaining_bytes -= BLOCK_SIZE;
  }
}

void __o_write_i64(void *dst_base, size_t dst_size, int64_t *addr,
                   int64_t val) {
  assert(IS_64_BIT_ALIGNED(addr));
  assert(IS_BLOCK_ALIGNED(dst_base));

  // initialize the index vector
  const int chunk_offset =
      (int)((uintptr_t)addr - (uintptr_t)dst_base) % CHUNK_SIZE_I64;
  const int block_offset = chunk_offset % BLOCK_SIZE;
  int64_t remaining_bytes = dst_size;
  const uint8_t *chunk = dst_base;

#ifdef __LIBOBLIVIOUS_USE_VPGATHER__
  __m256i vindex = _mm256_set_epi64x(
      (3 * BLOCK_SIZE) + block_offset, (2 * BLOCK_SIZE) + block_offset,
      (1 * BLOCK_SIZE) + block_offset, (0 * BLOCK_SIZE) + block_offset);

  for (; remaining_bytes >= CHUNK_SIZE_I64;
       chunk += CHUNK_SIZE_I64, remaining_bytes -= CHUNK_SIZE_I64) {
    int64_t *_chunk = (int64_t *)chunk;
    // gather the values from the region of memory of size
    // `CHUNK_SIZE_I64`
    const __m256i read_values =
        _mm256_i64gather_epi64((const long long int *)chunk, vindex, 1);

    // rewrite all values, only capturing the desired value once
#define COPY_VALUE_AT_INDEX_64(index)                                          \
  {                                                                            \
    const int64_t read_value = _mm256_extract_epi64(read_values, index);       \
    const size_t chunk_offset =                                                \
        (index * BLOCK_SIZE + block_offset) / sizeof(int64_t);                 \
    _chunk[chunk_offset] =                                                     \
        o_copy_i64(_chunk + chunk_offset == addr, val, read_value);            \
  }
    COPY_VALUE_AT_INDEX_64(0);
    COPY_VALUE_AT_INDEX_64(1);
    COPY_VALUE_AT_INDEX_64(2);
    COPY_VALUE_AT_INDEX_64(3);
  }
#endif

  const uint8_t *block = chunk;
  while (remaining_bytes > 0) {
    // The remaining bytes are fewer than the chunk size, so don't read/write
    // beyond the end of permissible memory!
    int64_t *_dst = (int64_t *)(block + block_offset);
    *_dst = o_copy_i64(_dst == addr, val, *_dst);
    block += BLOCK_SIZE;
    remaining_bytes -= BLOCK_SIZE;
  }
}

void __o_write_list_i32(const struct o_mem_node *dst_list, int32_t *addr,
                        int32_t val, bool list_aligned) {
  for (const struct o_mem_node *I = dst_list, *const E = NULL; I != E;
       I = I->next) {
    int32_t *dst_base = I->base_addr;
    size_t dst_size = I->size;
    if (!list_aligned) {
      ALIGN_TO_MASK(dst_base, dst_size, BLOCK_MASK);
    }
    __o_write_i32(dst_base, dst_size, addr, val);
  }
}

void __o_write_list_i64(const struct o_mem_node *dst_list, int64_t *addr,
                        int64_t val, bool list_aligned) {
  for (const struct o_mem_node *I = dst_list, *const E = NULL; I != E;
       I = I->next) {
    int64_t *dst_base = I->base_addr;
    size_t dst_size = I->size;
    if (!list_aligned) {
      ALIGN_TO_MASK(dst_base, dst_size, BLOCK_MASK);
    }
    __o_write_i64(dst_base, dst_size, addr, val);
  }
}

void __o_write(void *dst_base, size_t dst_size, void *addr,
               bool addr_is_array_elem, const void *src, size_t bytes_to_write,
               bool base_aligned) {
  if (addr_is_array_elem && bytes_to_write >= BLOCK_SIZE) {
    uint8_t *_dst_base = dst_base;
    for (size_t i = 0; i < dst_size; i += bytes_to_write) {
      o_copy(_dst_base + i, _dst_base + i == addr, src, _dst_base + i,
             bytes_to_write);
    }
  } else if (addr_is_array_elem && IS_64_BIT_ALIGNED(dst_base) &&
             bytes_to_write % sizeof(int64_t) == 0) {
    if (!base_aligned) {
      ALIGN_TO_MASK(dst_base, dst_size, BLOCK_MASK);
    }
    const int64_t *_src = src;
    int64_t *_addr = addr;
    for (size_t j = 0; j < bytes_to_write / sizeof(int64_t); ++j) {
      __o_write_i64(dst_base, dst_size, _addr + j, *_src);
    }
  } else {
    if (!base_aligned) {
      ALIGN_TO_MASK(dst_base, dst_size, BLOCK_MASK);
    }
    const int32_t *_src = src;
    int32_t *_addr = addr;
    for (size_t j = 0; j < bytes_to_write / sizeof(int32_t); ++j) {
      __o_write_i32(dst_base, dst_size, _addr + j, _src[j]);
    }
  }
}

void __o_write_list(const struct o_mem_node *dst_list, void *addr,
                    bool addr_is_array_elem, const void *src,
                    size_t bytes_to_write, bool list_aligned) {
  for (const struct o_mem_node *I = dst_list, *const E = NULL; I != E;
       I = I->next) {
    void *dst_base = I->base_addr;
    size_t dst_size = I->size;
    __o_write(dst_base, dst_size, addr, addr_is_array_elem, src, bytes_to_write,
              list_aligned);
  }
}
