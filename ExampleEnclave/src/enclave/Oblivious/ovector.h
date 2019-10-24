//===--------------- ovector.h - Oblivious vector container ---------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OVECTOR_H__
#define __OBLIVIOUS_OVECTOR_H__

#include "O.h"
#include "omemory.h"
#include <vector>

namespace oblivious {

template <typename T,
          AllocatorCategory C = AllocatorCategory::ContiguousAllocator>
using ovector = std::vector<T, oallocator<T, C>>;

} // namespace oblivious

#endif
