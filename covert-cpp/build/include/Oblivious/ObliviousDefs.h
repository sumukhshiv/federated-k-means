//===-------- ObliviousDefs.h.in - Architecture-dependent constants -------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OBLIVIOUS_DEFS_H__
#define __OBLIVIOUS_OBLIVIOUS_DEFS_H__

#include <immintrin.h>

#define MEMORY_MASK_BITS 6
#define BLOCK_SIZE (1 << MEMORY_MASK_BITS)
#define BLOCK_MASK ((uintptr_t)(BLOCK_SIZE - 1))
// A chunk is the maximal contiguous region of memory that can be
// simultaneously accessed by a single \c vpgatherdd.
#define CHUNK_SIZE_I32 ((sizeof(__m256i) / sizeof(int32_t)) * BLOCK_SIZE)
#define CHUNK_SIZE_I64 ((sizeof(__m256i) / sizeof(int64_t)) * BLOCK_SIZE)

#endif
