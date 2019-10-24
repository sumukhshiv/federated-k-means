//===- Oblivious.h - The libOblivious C primitives (o_read, o_copy, etc.) -===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OBLIVIOUS_H__
#define __OBLIVIOUS_OBLIVIOUS_H__

#include "__oblivious_impl.h"
#ifdef __cplusplus
#include <utility>
#endif

/**
 * \defgroup OBLIVIOUS libOblivious
 * \brief API for oblivious memory operations.
 *
 * **Note:** The C++ template interface for oblivious containers and algorithms
 * is described in the #oblivious namespace.
 *
 * A memory operation is oblivious if it does not leak information about
 * program data through a side channel. Program data can be leaked, for
 * instance, when a value influences a branch instruction or a memory access
 * operand. This library defines three categories of oblivious operations
 * on memory.
 *
 * Oblivious Copy
 * ------------------
 *
 * The oblivious copy operations are similar to the ternary `?:` operator.
 * For example,
 * ```C++
 * int o_foo(int *dst, bool c, int *left, int *right, int i) {
 *   o_copy_i32(dst[i], c, left[i], right[i]);
 *   return x;
 * }
 * ```
 * will return `left[i]` if `c` is `true`, and `right[i]` if `c` is `false`. It
 * is logically equivalent to writing
 * ```C++
 * int t_foo(int *dst, bool c, int *left, int *right, int i) {
 *   dst[i] = c ? left[i] : right[i];
 *   return x;
 * }
 * ```
 * However, the ternary `?:` operator will almost always compile with a branch
 * operation contingent on the value of `c`. Hence, the value of `c` may leak
 * through a side channel during execution. The o_foo() operation, for instance,
 * will always compile to the following instructions, regardless of compiler
 * optimizations:
 * ```assembly
 * movl    (%r9,%r8,4), %eax
 * movl    (%r10,%r8,4), %edx
 * testl   %esi, %esi
 * cmovel  %edx, %eax
 * movl    %eax, (%rdi,%r8,4)
 * ```
 * The o_foo() parameters are mapped into registers as follows:
 * | Parameter | Register |
 * | --------- | -------- |
 * | `dst`     | `%%rdi`  |
 * | `cond`    | `%%esi`  |
 * | `left`    | `%%r9`   |
 * | `right`   | `%%r10`  |
 * | `i`       | `%%r8`   |
 *
 * o_copy_i32() uses the conditional move instruction `cmov`
 * instead of a conditional branch. Moreover, o_copy_i32() cannot be optimized
 * away, so the `left[i]` and `right[i]` operands must be read from memory
 * regardless of the value of `cond`. These features make o_copy_i32()
 * oblivious.
 *
 * Oblivious Read/Write
 * -----------------------
 *
 * Oblivious reads and writes perform memory accesses in an oblivious manner.
 * For example, given arrays `int is[4096]` and `C cs[1024]` where `C`
 * is some trivially copiable C++ class, the following are equivalent:
 *
 * | Non-oblivious access | Oblivious access                                   |
 * | -------------------- | -------------------------------------------------- |
 * | `is[i]`              | `o_read_i32(is, sizeof(is), is + i)`               |
 * | `is[i] = ival`       | `o_write_i32(is, sizeof(is), is + i, ival)`        |
 * | `cs[i]`              | `o_read_T(cs, sizeof(cs), cs + i)`                 |
 * | `cs[i] = cval`       | `o_write_T(cs, sizeof(cs), cs + i, cval)`          |
 *
 * Note that the `o_*_T` operators are only available to C++ clients. There are
 * also faster versions of these functions, `o_*a_*()` which operate on memory
 * regions that are aligned along the cache line boundary, e.g. 64 bytes on x86.
 * However, if they are used to read from/write to memory regions which are not
 * properly aligned, then this may leak data through a side channel.
 *
 * These functions all work by "touching" every cache block covered by the
 * array on each access. On platforms with AVX2 instructions, this means using
 * the VPGATHER* instructions to simultaneously touch several cache lines in one
 * operation.
 *
 * @{
 */

/**
 * \brief Copy a byte from one of two registers.
 *
 * Performs an oblivious ternary-like copy of one byte. Equivalent to
 * \code
 * cond ? left : right
 * \endcode
 */
static inline int8_t o_copy_i8(int cond, int8_t left, int8_t right) {
#if defined(__GNUC__) || defined(__GNUG__)
  __asm__ volatile("test %[cond], %[cond]\n\t"
                   "cmovz %w[right], %w[left]\n\t"
                   : [ left ] "+r"(left)
                   : [ right ] "r"(right), [ cond ] "r"(cond)
                   : "cc");
  return left;
#elif defined(_MSC_VER)
  return __o_copy_i8(cond, left, right);
#endif
}

/**
 * \brief Copy a short from one of two registers.
 *
 * Performs an oblivious ternary-like copy of one (16-bit) short. Equivalent to
 * \code
 * cond ? left : right
 * \endcode
 */
static inline int16_t o_copy_i16(int cond, int16_t left, int16_t right) {
#if defined(__GNUC__) || defined(__GNUG__)
  __asm__ volatile("test %[cond], %[cond]\n\t"
                   "cmovz %[right], %[left]\n\t"
                   : [ left ] "+r"(left)
                   : [ right ] "r"(right), [ cond ] "r"(cond)
                   : "cc");
  return left;
#elif defined(_MSC_VER)
  return __o_copy_i16(cond, left, right);
#endif
}

/**
 * \brief Copy an int from one of two registers.
 *
 * Performs an oblivious ternary-like copy of one (32-bit) int. Equivalent to
 * \code
 * cond ? left : right
 * \endcode
 */
static inline int32_t o_copy_i32(int cond, int32_t left, int32_t right) {
#if defined(__GNUC__) || defined(__GNUG__)
  __asm__ volatile("test %[cond], %[cond]\n\t"
                   "cmovz %[right], %[left]\n\t"
                   : [ left ] "+r"(left)
                   : [ right ] "r"(right), [ cond ] "r"(cond)
                   : "cc");
  return left;
#elif defined(_MSC_VER)
  return __o_copy_i32(cond, left, right);
#endif
}

/**
 * \brief Copy a long int from one of two registers.
 *
 * Performs an oblivious ternary-like copy of one (64-bit) long int. Equivalent
 * to
 * \code
 * cond ? left : right
 * \endcode
 */
static inline int64_t o_copy_i64(int cond, int64_t left, int64_t right) {
#if defined(__GNUC__) || defined(__GNUG__)
  __asm__ volatile("test %[cond], %[cond]\n\t"
                   "cmovz %[right], %[left]\n\t"
                   : [ left ] "+r"(left)
                   : [ right ] "r"(right), [ cond ] "r"(cond)
                   : "cc");
  return left;
#elif defined(_MSC_VER)
  return __o_copy_i64(cond, left, right);
#endif
}

/**
 * \brief Copy a 256-bit vector
 *
 * Performs an oblivious ternary-like copy of one (256-bit) vector. Equivalent
 * to
 * \code dst[offset] = cond ? left[offset] : right[offset]
 * \endcode
 */
static inline void o_copy_i256(__m256i *dst, int cond, const __m256i *left,
                               const __m256i *right, size_t offset) {
  const __m256i mask = _mm256_set1_epi32(!!cond - 1);
  const __m256i ltmp = _mm256_loadu_si256(left + offset);
  const __m256i rtmp = _mm256_loadu_si256(right + offset);
  const __m256i result = _mm256_blendv_epi8(ltmp, rtmp, mask);
  _mm256_storeu_si256(dst + offset, result);
}

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Copy \p n bytes to \p dst.
 *
 * Note that this operation cannot be inlined, and thus may be much slower than
 * other o_copy*() operations. Use this operation only when the number of bytes
 * to copy cannot be determined at compile time.
 */
EXPORT void o_copy(void *dst, int cond, const void *left, const void *right,
                   size_t n);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <type_traits>

/**
 * \brief Copy \p NumVals integer values to \p dst.
 *
 * This operation is very fast, because it can be inlined.
 */
template <size_t NumVals>
inline void o_copy_arr(int32_t *dst, bool c, const int32_t *left,
                       const int32_t *right) {
  size_t i = 0;

  {
    typedef __m256i _t;
    const size_t ints_per_t = sizeof(_t) / sizeof(int32_t);
    for (; i + ints_per_t <= NumVals; i += ints_per_t) {
      o_copy_i256(reinterpret_cast<_t *>(dst), c,
                  reinterpret_cast<const _t *>(left),
                  reinterpret_cast<const _t *>(right), i / ints_per_t);
    }
  }

  {
    typedef int64_t _t;
    const size_t ints_per_t = sizeof(_t) / sizeof(int32_t);
    for (; i + ints_per_t <= NumVals; i += ints_per_t) {
      const size_t _i = i / ints_per_t;
      reinterpret_cast<_t *>(dst)[_i] =
          o_copy_i64(c, reinterpret_cast<const _t *>(left)[_i],
                     reinterpret_cast<const _t *>(right)[_i]);
    }
  }

  if (i < NumVals) {
    dst[i] = o_copy_i32(c, left[i], right[i]);
  }
}

/**
 * \brief Copy to \p dst.
 *
 * This operation is very fast, because it can be inlined.
 *
 * **Note**: \p T must be trivially copiable (it cannot have a user-defined
 * copy constructor).
 */
template <typename T>
inline void o_copy_T(T &dst, bool c, const T &left, const T &right) {
  static_assert(sizeof(T) % sizeof(int32_t) == 0,
                "sizeof(T) must be a multiple of sizeof(int32_t)");
  // static_assert(std::is_trivially_copyable<T>::value,
  //"T must be trivially copiable"); // FIXME
  static_assert(std::is_default_constructible<T>::value,
                "T must be trivially copiable");
  o_copy_arr<sizeof(T) / sizeof(int32_t)>(
      reinterpret_cast<int32_t *>(std::addressof(dst)), c,
      reinterpret_cast<const int32_t *>(std::addressof(left)),
      reinterpret_cast<const int32_t *>(std::addressof(right)));
}

#endif // __cplusplus

/**
 * \brief Obliviously swap the contents of two 8-bit memory locations.
 *
 * Equivalent to
 * \code
 * if (cond) {
 *   int8_t tmp = *left;
 *   *left = *right;
 *   *right = tmp;
 * }
 * \endcode
 */
static inline void o_swap_i8(int cond, int8_t *left, int8_t *right) {
#if defined(__GNUC__) || defined(__GNUG__)
  int8_t _left, _right, _tmp;
  __asm__ volatile(
      "test %[cond], %[cond]\n\t"
      "mov (%[right]), %[_right]\n\t"
      "mov (%[left]), %[_left]\n\t"
      "mov %[_left], %[_tmp]\n\t"
      "cmovnz %w[_right], %w[_left]\n\t"
      "cmovnz %w[_tmp], %w[_right]\n\t"
      "mov %[_left], (%[left])\n\t"
      "mov %[_right], (%[right])\n\t"
      : [ _left ] "=&r"(_left), [ _right ] "=&r"(_right), [ _tmp ] "=&r"(_tmp)
      : [ left ] "r"(left), [ right ] "r"(right), [ cond ] "r"(cond)
      : "cc", "memory");
#elif defined(_MSC_VER)
  __o_swap_i8(cond, left, right);
#endif
}

/**
 * \brief Obliviously swap the contents of two 16-bit memory locations.
 *
 * Equivalent to
 * \code
 * if (cond) {
 *   int16_t tmp = *left;
 *   *left = *right;
 *   *right = tmp;
 * }
 * \endcode
 */
static inline void o_swap_i16(int cond, int16_t *left, int16_t *right) {
#if defined(__GNUC__) || defined(__GNUG__)
  int16_t _left, _right, _tmp;
  __asm__ volatile(
      "test %[cond], %[cond]\n\t"
      "mov (%[right]), %[_right]\n\t"
      "mov (%[left]), %[_left]\n\t"
      "mov %[_left], %[_tmp]\n\t"
      "cmovnz %[_right], %[_left]\n\t"
      "cmovnz %[_tmp], %[_right]\n\t"
      "mov %[_left], (%[left])\n\t"
      "mov %[_right], (%[right])\n\t"
      : [ _left ] "=&r"(_left), [ _right ] "=&r"(_right), [ _tmp ] "=&r"(_tmp)
      : [ left ] "r"(left), [ right ] "r"(right), [ cond ] "r"(cond)
      : "cc", "memory");
#elif defined(_MSC_VER)
  __o_swap_i16(cond, left, right);
#endif
}

/**
 * \brief Obliviously swap the contents of two 32-bit memory locations.
 *
 * Equivalent to
 * \code
 * if (cond) {
 *   int32_t tmp = *left;
 *   *left = *right;
 *   *right = tmp;
 * }
 * \endcode
 */
static inline void o_swap_i32(int cond, int32_t *left, int32_t *right) {
#if defined(__GNUC__) || defined(__GNUG__)
  int32_t _left, _right, _tmp;
  __asm__ volatile(
      "test %[cond], %[cond]\n\t"
      "mov (%[right]), %[_right]\n\t"
      "mov (%[left]), %[_left]\n\t"
      "mov %[_left], %[_tmp]\n\t"
      "cmovnz %[_right], %[_left]\n\t"
      "cmovnz %[_tmp], %[_right]\n\t"
      "mov %[_left], (%[left])\n\t"
      "mov %[_right], (%[right])\n\t"
      : [ _left ] "=&r"(_left), [ _right ] "=&r"(_right), [ _tmp ] "=&r"(_tmp)
      : [ left ] "r"(left), [ right ] "r"(right), [ cond ] "r"(cond)
      : "cc", "memory");
#elif defined(_MSC_VER)
  __o_swap_i32(cond, left, right);
#endif
}

/**
 * \brief Obliviously swap the contents of two 64-bit memory locations.
 *
 * Equivalent to
 * \code
 * if (cond) {
 *   int64_t tmp = *left;
 *   *left = *right;
 *   *right = tmp;
 * }
 * \endcode
 */
static inline void o_swap_i64(int cond, int64_t *left, int64_t *right) {
#if defined(__GNUC__) || defined(__GNUG__)
  int64_t _left, _right, _tmp;
  __asm__ volatile(
      "test %[cond], %[cond]\n\t"
      "mov (%[right]), %[_right]\n\t"
      "mov (%[left]), %[_left]\n\t"
      "mov %[_left], %[_tmp]\n\t"
      "cmovnz %[_right], %[_left]\n\t"
      "cmovnz %[_tmp], %[_right]\n\t"
      "mov %[_left], (%[left])\n\t"
      "mov %[_right], (%[right])\n\t"
      : [ _left ] "=&r"(_left), [ _right ] "=&r"(_right), [ _tmp ] "=&r"(_tmp)
      : [ left ] "r"(left), [ right ] "r"(right), [ cond ] "r"(cond)
      : "cc", "memory");
#elif defined(_MSC_VER)
  __o_swap_i64(cond, left, right);
#endif
}

/**
 * \brief Swap two 256-bit memory chunks.
 *
 * Equivalent to
 * \code
 * for (int i = 0; i < 8; ++i) {
 *   int32_t tmp = left[i];
 *   left[i] = right[i];
 *   right[i] = tmp;
 * }
 * \endcode
 */
static inline void o_swap_i256(int cond, __m256i *left, __m256i *right) {
  const __m256i mask = _mm256_set1_epi32(!!cond - 1);
  __m256i _left = _mm256_loadu_si256(left);
  __m256i _right = _mm256_loadu_si256(right);
  __m256i _tmp = _left;
  _left = _mm256_blendv_epi8(_right, _left, mask);
  _right = _mm256_blendv_epi8(_tmp, _right, mask);
  _mm256_storeu_si256(left, _left);
  _mm256_storeu_si256(right, _right);
}

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Obliviously swap \p n bytes between \p left and \p right.
 *
 * Note that this operation cannot be inlined, and thus may be much slower than
 * other o_swap*() operations. Use this operation only when the number of bytes
 * to swap cannot be determined at compile time.
 */
EXPORT void o_swap(int cond, void *left, void *right, size_t n);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <type_traits>

/**
 * \brief Obliviously swap \p NumVals integer values between \p left and \p
 * right.
 *
 * This operation is very fast, because it can be inlined.
 */
template <size_t NumVals>
inline void o_swap_arr(bool c, int32_t *left, int32_t *right) {
  size_t i = 0;

  {
    typedef __m256i _t;
    const size_t ints_per_t = sizeof(_t) / sizeof(int32_t);
    for (; i + ints_per_t <= NumVals; i += ints_per_t) {
      o_swap_i256(c, reinterpret_cast<_t *>(left + i),
                  reinterpret_cast<_t *>(right + i));
    }
  }

  {
    typedef int64_t _t;
    const size_t ints_per_t = sizeof(_t) / sizeof(int32_t);
    for (; i + ints_per_t <= NumVals; i += ints_per_t) {
      o_swap_i64(c, reinterpret_cast<_t *>(left + i),
                 reinterpret_cast<_t *>(right + i));
    }
  }

  if (i < NumVals) {
    o_swap_i32(c, left + i, right + i);
  }
}

/**
 * \brief Obliviously swap \p left and \p right.
 *
 * This operation is very fast, because it can be inlined.
 *
 * **Note**: \p T must be trivially copiable (it cannot have a user-defined
 * copy constructor) and its size must be a multiple of `sizeof(int32_t)`.
 */
template <typename T> inline void o_swap_T(bool c, T &left, T &right) {
  static_assert(sizeof(T) % sizeof(int32_t) == 0,
                "sizeof(T) must be a multiple of sizeof(int32_t)");
  static_assert(std::is_trivially_copyable<T>::value,
                "T must be trivially copiable");
  static_assert(std::is_default_constructible<T>::value,
                "T must be trivially copiable");
  o_swap_arr<sizeof(T) / sizeof(int32_t)>(
      c, reinterpret_cast<int32_t *>(std::addressof(left)),
      reinterpret_cast<int32_t *>(std::addressof(right)));
}

#endif // __cplusplus

#define ALIGN_TO_MASK(mem_base, mem_size, mask)                                \
  {                                                                            \
    mem_size += ((uintptr_t)mem_base & mask);                                  \
    mem_base = (void *)((uintptr_t)mem_base & ~mask);                          \
  }

struct o_mem_node {
  struct o_mem_node *next;
  void *base_addr;
  size_t size;
};

static inline bool is_within_one_block(const void *base, size_t size,
                                       bool base_aligned) {
  if (base_aligned) {
    return size <= BLOCK_SIZE;
  } else {
    return ((uintptr_t)base & BLOCK_MASK) + size <= BLOCK_SIZE;
  }
}

static inline bool is_within_one_block_list(const struct o_mem_node *lst,
                                            bool lst_aligned) {
  if (lst->next) {
    return false;
  }

  if (lst_aligned) {
    return lst->size <= BLOCK_SIZE;
  } else {
    return ((uintptr_t)lst->base_addr & BLOCK_MASK) + lst->size <= BLOCK_SIZE;
  }
}

/**
 * \brief Obliviously read a 32-bit integer from a location within a given list
 * of memory regions.
 *
 * \param src_list List of memory regions from which to obliviously read.
 * \param addr Address from which to read. **Must be 4-byte aligned**
 * \param list_aligned Asserts that every memory region referenced by \p
 *        src_list is aligned to the beginning of a block (this enables several
 *        optimizations).
 */
static inline int32_t o_read_list_i32(const struct o_mem_node *src_list,
                                      const int32_t *addr, bool list_aligned) {
  if (is_within_one_block_list(src_list, list_aligned)) {
    return *addr;
  } else {
    int32_t ret;
    __o_read_list_i32(&ret, src_list, addr, list_aligned);
    return ret;
  }
}

/**
 * \brief Obliviously read a 64-bit integer from a location within a given list
 * of memory regions.
 *
 * \param src_list List of memory regions from which to obliviously read.
 * \param addr Address from which to read. **Must be 8-byte aligned**
 * \param list_aligned Asserts that every memory region referenced by \p
 *        src_list is aligned to the beginning of a block (this enables several
 *        optimizations).
 */
static inline int64_t o_read_list_i64(const struct o_mem_node *src_list,
                                      const int64_t *addr, bool list_aligned) {
  if (is_within_one_block_list(src_list, list_aligned)) {
    return *addr;
  } else {
    int64_t ret;
    __o_read_list_i64(&ret, src_list, addr, list_aligned);
    return ret;
  }
}

/**
 * \brief Obliviously read a 32-bit integer from location within a given memory
 * region.
 *
 * \param src_base The base of the memory region.
 * \param src_size The size of the memory region, in bytes.
 * \param addr Address from which to read. **Must be 4-byte aligned**
 * \param base_aligned Asserts that \p src_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
static inline int32_t o_read_i32(const void *src_base, size_t src_size,
                                 const int32_t *addr, bool base_aligned) {
  if (is_within_one_block(src_base, src_size, base_aligned)) {
    return *addr;
  } else {
    int32_t ret;
    if (!base_aligned) {
      ALIGN_TO_MASK(src_base, src_size, BLOCK_MASK);
    }
    __o_read_i32(&ret, src_base, src_size, addr);
    return ret;
  }
}

/**
 * \brief Obliviously read a 64-bit integer from a location within a given
 * memory region.
 *
 * \param src_base The base of the memory region.
 * \param src_size The size of the memory region, in bytes.
 * \param addr Address from which to read. **Must be 8-byte aligned**
 * \param base_aligned Asserts that \p src_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
static inline int64_t o_read_i64(const void *src_base, size_t src_size,
                                 const int64_t *addr, bool base_aligned) {
  if (is_within_one_block(src_base, src_size, base_aligned)) {
    return *addr;
  } else {
    int64_t ret;
    if (!base_aligned) {
      ALIGN_TO_MASK(src_base, src_size, BLOCK_MASK);
    }
    __o_read_i64(&ret, src_base, src_size, addr);
    return ret;
  }
}

/**
 * \brief Obliviously read data from a location within a given list of memory
 * regions.
 *
 * \param dst Destination to which the read bytes will be copied.
 * \param bytes_to_read Number of byts to read from \p addr
 * \param src_list List of memory regions from which to obliviously read.
 * \param addr Address from which to read. **Must be 4-byte aligned**
 * \param addr_is_array_elem Should be \c true if \p src_list is a list of
 *        homogeneous arrays containing elements of size \p bytes_to_read, and
 *        \p addr refers to an element in one of these arrays. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param list_aligned Asserts that every memory region referenced by
 *        \p src_list is aligned to the beginning of a block (this enables
 *        several optimizations).
 */
static inline void o_read_list(void *dst, size_t bytes_to_read,
                               const struct o_mem_node *src_list,
                               const void *addr, bool addr_is_array_elem,
                               bool list_aligned) {
  if (is_within_one_block_list(src_list, list_aligned)) {
    int32_t *_dst = (int32_t *)dst;
    const int32_t *_addr = (const int32_t *)addr;
    for (size_t i = 0; i < bytes_to_read / sizeof(int32_t); ++i) {
      _dst[i] = _addr[i];
    }
  } else {
    __o_read_list(dst, bytes_to_read, src_list, addr, addr_is_array_elem,
                  list_aligned);
  }
}

/**
 * \brief Obliviously read data from a location within a given memory region.
 *
 * \param dst Destination to which the read bytes will be copied.
 * \param bytes_to_read Number of byts to read from \p addr
 * \param src_base The base of the source memory region.
 * \param src_size The size of the source memory region, in bytes.
 * \param addr Address from which to begin reading. **Must be 4-byte aligned**
 * \param addr_is_array_elem Should be \c true if \p src_base is a
 *        homogeneous array containing elements of size \p bytes_to_read, and
 *        \p addr refers to an element in that array. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param base_aligned Asserts that \p src_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
static inline void o_read(void *dst, size_t bytes_to_read, const void *src_base,
                          size_t src_size, const void *addr,
                          bool addr_is_array_elem, bool base_aligned) {
  if (is_within_one_block(src_base, src_size, base_aligned)) {
    int32_t *_dst = (int32_t *)dst;
    const int32_t *_addr = (const int32_t *)addr;
    for (size_t i = 0; i < bytes_to_read / sizeof(int32_t); ++i) {
      _dst[i] = _addr[i];
    }
  } else {
    __o_read(dst, bytes_to_read, src_base, src_size, addr, addr_is_array_elem,
             base_aligned);
  }
}

#ifdef __cplusplus

/**
 * \brief Obliviously read a value of type \p T from a location within a
 * given list of memory regions.
 *
 * \tparam T The type of the element to read. **`sizeof(T)` must be a multiple
 *         of 4, and `alignof(T)` must be a multiple of 4**
 * \param src_list List of memory regions from which to obliviously read.
 * \param addr Address from which to read. **Must be 4-byte aligned**
 * \param addr_is_array_elem Should be \c true if \p src_list is a list of
 *        homogeneous arrays containing elements of type \p T, and
 *        \p addr refers to an element in one of these arrays. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param list_aligned Asserts that every memory region referenced by \p
 *        src_list is aligned to the beginning of a block (this enables several
 *        optimizations).
 */
template <typename T>
inline T o_read_list_T(const o_mem_node *src_list, const T *addr,
                       bool addr_is_array_elem = false,
                       bool list_aligned = false) {
  static_assert(std::is_trivially_copyable<T>::value,
                "T must be trivially copiable");
  static_assert(sizeof(T) % sizeof(int32_t) == 0,
                "sizeof(T) must be a multiple of sizeof(int32_t)");
  static_assert(alignof(T) % alignof(int32_t) == 0,
                "alignof(T) must be a multiple of alignof(int32_t)");
  T ret;
  o_read_list(std::addressof(ret), sizeof(T), src_list, addr,
              addr_is_array_elem, list_aligned);
  return ret;
}

/**
 * \brief Obliviously read a value of type \p T from a location within a given
 * memory region.
 *
 * \tparam T The type of the element to read. **`sizeof(T)` must be a multiple
 *         of 4, and `alignof(T)` must be a multiple of 4**
 * \param src_base The base of the source memory region.
 * \param src_size Size of the source memory region, in bytes.
 * \param addr Address from which to read. **Must be 4-byte aligned**
 * \param addr_is_array_elem Should be \c true if \p src_base is a
 *        homogeneous array containing elements of type \p T, and
 *        \p addr refers to an element in one of these arrays. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param base_aligned Asserts that \p src_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
template <typename T>
inline T o_read_T(const void *src_base, size_t src_size, const T *addr,
                  bool addr_is_array_elem = false, bool base_aligned = false) {
  static_assert(std::is_trivially_copyable<T>::value,
                "T must be trivially copiable");
  static_assert(std::is_default_constructible<T>::value,
                "T must be trivially copiable");
  static_assert(sizeof(T) % sizeof(int32_t) == 0,
                "sizeof(T) must be a multiple of sizeof(int32_t)");
  static_assert(alignof(T) % alignof(int32_t) == 0,
                "alignof(T) must be a multiple of alignof(int32_t)");
  T ret;
  o_read(std::addressof(ret), sizeof(T), src_base, src_size, addr,
         addr_is_array_elem, base_aligned);
  return ret;
}

#endif

/**
 * \brief Obliviously write a 32-bit integer to a location within a given list
 * of memory regions.
 *
 * \param dst_list List of memory regions to which to obliviously write.
 * \param addr Address to which to write. **Must be 4-byte aligned**
 * \param val Value to write to `*addr`.
 * \param list_aligned Asserts that every memory region referenced by \p
 *        dst_list is aligned to the beginning of a block (this enables several
 *        optimizations).
 */
static inline void o_write_list_i32(const struct o_mem_node *dst_list,
                                    int32_t *addr, int32_t val,
                                    bool list_aligned) {
  if (is_within_one_block_list(dst_list, list_aligned)) {
    *addr = val;
  } else {
    __o_write_list_i32(dst_list, addr, val, list_aligned);
  }
}

/**
 * \brief Obliviously write a 64-bit integer to a location within a given list
 * of memory regions.
 *
 * \param dst_list List of memory regions to which to obliviously write.
 * \param addr Address to which to write. **Must be 8-byte aligned**
 * \param val Value to write to `*addr`.
 * \param list_aligned Asserts that every memory region referenced by \p
 *        dst_list is aligned to the beginning of a block (this enables several
 *        optimizations).
 */
static inline void o_write_list_i64(const struct o_mem_node *dst_list,
                                    int64_t *addr, int64_t val,
                                    bool list_aligned) {
  if (is_within_one_block_list(dst_list, list_aligned)) {
    *addr = val;
  } else {
    __o_write_list_i64(dst_list, addr, val, list_aligned);
  }
}

/**
 * \brief Obliviously write a 32-bit integer to a memory region.
 *
 * \param dst_base The base of the memory region.
 * \param dst_size Size of the memory region in bytes.
 * \param addr Address to which to write. **Must be 4-byte aligned**
 * \param val The value to write to `*addr`.
 * \param base_aligned Asserts that \p dst_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
static inline void o_write_i32(void *dst_base, size_t dst_size, int32_t *addr,
                               int32_t val, bool base_aligned) {
  if (is_within_one_block(dst_base, dst_size, base_aligned)) {
    *addr = val;
  } else {
    if (!base_aligned) {
      ALIGN_TO_MASK(dst_base, dst_size, BLOCK_MASK);
    }
    __o_write_i32(dst_base, dst_size, addr, val);
  }
}

/**
 * \brief Obliviously write a 64-bit integer to a memory region.
 *
 * \param dst_base The base of the memory region.
 * \param dst_size Size of the memory region in bytes.
 * \param addr Address to which to write. **Must be 8-byte aligned**
 * \param val The value to write to `*addr`.
 * \param base_aligned Asserts that \p dst_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
static inline void o_write_i64(void *dst_base, size_t dst_size, int64_t *addr,
                               int64_t val, bool base_aligned) {
  if (is_within_one_block(dst_base, dst_size, base_aligned)) {
    *addr = val;
  } else {
    if (!base_aligned) {
      ALIGN_TO_MASK(dst_base, dst_size, BLOCK_MASK);
    }
    __o_write_i64(dst_base, dst_size, addr, val);
  }
}

/**
 * \brief Obliviously write data to a location within a given list
 * of memory regions.
 *
 * \param dst_list List of memory regions to which to obliviously write.
 * \param addr Address to which to write. **Must be 4-byte aligned**
 * \param addr_is_array_elem Should be \c true if \p dst_list is a list of
 *        homogeneous arrays containing elements of size \p bytes_to_write, and
 *        \p addr refers to an element in one of these arrays. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param src The source buffer.
 * \param bytes_to_write Number of bytes to copy from \p src to \p addr
 * \param list_aligned Asserts that every memory region referenced by \p
 *        dst_list is aligned to the beginning of a block (this enables several
 *        optimizations).
 */
static inline void o_write_list(const struct o_mem_node *dst_list, void *addr,
                                bool addr_is_array_elem, const void *src,
                                size_t bytes_to_write, bool list_aligned) {
  if (is_within_one_block_list(dst_list, list_aligned)) {
    const int32_t *_src = (const int32_t *)src;
    int32_t *_addr = (int32_t *)addr;
    for (size_t i = 0; i < bytes_to_write / sizeof(int32_t); ++i) {
      _addr[i] = _src[i];
    }
  } else {
    __o_write_list(dst_list, addr, addr_is_array_elem, src, bytes_to_write,
                   list_aligned);
  }
}

/**
 * \brief Obliviously write data to a memory region.
 *
 * \param dst_base Base of the destination memory region.
 * \param dst_size The size of the destination memory region, in bytes.
 * \param addr Address to which the bytes should be written. **Must be
 *        4-byte aligned**
 * \param addr_is_array_elem Should be \c true if \p dst_base is a
 *        homogeneous array containing elements of size \p bytes_to_write, and
 *        \p addr refers to an element in one of these arrays. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param src The source buffer.
 * \param bytes_to_write Number of bytes to copy from \p src to \p addr
 * \param base_aligned Asserts that \p src_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
static inline void o_write(void *dst_base, size_t dst_size, void *addr,
                           bool addr_is_array_elem, const void *src,
                           size_t bytes_to_write, bool base_aligned) {
  if (is_within_one_block(dst_base, dst_size, base_aligned)) {
    const int32_t *_src = (const int32_t *)src;
    int32_t *_addr = (int32_t *)addr;
    for (size_t i = 0; i < bytes_to_write / sizeof(int32_t); ++i) {
      _addr[i] = _src[i];
    }
  } else {
    __o_write(dst_base, dst_size, addr, addr_is_array_elem, src, bytes_to_write,
              base_aligned);
  }
}

#ifdef __cplusplus

/**
 * \brief Obliviously write a value of type \p T to a location within a
 * given list of memory regions.
 *
 * \tparam T The type of the element to read. **`sizeof(T)` must be a multiple
 *         of 4, and `alignof(T)` must be a multiple of 4**
 * \param dst_list List of memory regions to which to obliviously write.
 * \param addr Address to which to write. **Must be 4-byte aligned**
 * \param val The value to write to `*addr`.
 * \param addr_is_array_elem Should be \c true if \p dst_list is a list of
 *        homogeneous arrays containing elements of type \p T, and
 *        \p addr refers to an element in one of these arrays. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param list_aligned Asserts that every memory region referenced by \p
 *        dst_list is aligned to the beginning of a block (this enables several
 *        optimizations).
 */
template <typename T>
inline void o_write_list_T(const o_mem_node *dst_list, T *addr, const T &val,
                           bool addr_is_array_elem = false,
                           bool list_aligned = false) {
  static_assert(std::is_trivially_copyable<T>::value,
                "T must be trivially copiable");
  static_assert(std::is_default_constructible<T>::value,
                "T must be trivially copiable");
  static_assert(sizeof(T) % sizeof(int32_t) == 0,
                "sizeof(T) must be a multiple of sizeof(int32_t)");
  static_assert(alignof(T) % alignof(int32_t) == 0,
                "alignof(T) must be a multiple of alignof(int32_t)");
  o_write_list(dst_list, addr, addr_is_array_elem, std::addressof(val),
               sizeof(T), list_aligned);
}

/**
 * \brief Obliviously write a value of type \p T to a memory region.
 *
 * \tparam T The type of the element to write. **`sizeof(T)` must be a multiple
 *         of 4, and `alignof(T) must be a multiple of 4`**
 * \param dst_base The base of the destination memory region.
 * \param dst_size Size of the destination memory region, in bytes.
 * \param addr Address to which to write. **Must be 4-byte aligned**
 * \param val The value to write to `*addr`.
 * \param addr_is_array_elem Should be \c true if \p dst_base is a
 *        homogeneous array containing elements of type \p T, and
 *        \p addr refers to an element in one of these arrays. This can enable
 *        several optimizations, but may return an incorrect result if these
 *        conditions are not actually satisfied.
 * \param base_aligned Asserts that \p dst_base is aligned to the beginning of
 *        a block (this enables several optimizations)
 */
template <typename T>
inline void o_write_T(void *dst_base, size_t dst_size, T *addr, const T &val,
                      bool addr_is_array_elem = false,
                      bool base_aligned = false) {
  static_assert(std::is_trivially_copyable<T>::value,
                "T must be trivially copiable");
  static_assert(std::is_default_constructible<T>::value,
                "T must be trivially copiable");
  static_assert(sizeof(T) % sizeof(int32_t) == 0,
                "sizeof(T) must be a multiple of sizeof(int32_t)");
  static_assert(alignof(T) % alignof(int32_t) == 0,
                "alignof(T) must be a multiple of alignof(int32_t)");
  o_write(dst_base, dst_size, addr, addr_is_array_elem, std::addressof(val),
          sizeof(T), base_aligned);
}

#endif

/**
 * @}
 */

#endif
