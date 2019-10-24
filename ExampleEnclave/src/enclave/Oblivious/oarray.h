//===---------------- oarray.h - Oblivious array container ----------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OARRAY_H__
#define __OBLIVIOUS_OARRAY_H__

#include "O.h"
#include <array>

namespace oblivious {

template <typename T, std::size_t N>
struct alignas(BLOCK_SIZE) oarray : public std::array<T, N> {};

} // end namespace oblivious

#endif
