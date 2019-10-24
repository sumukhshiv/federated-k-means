//===---------------- odeque.h - Oblivious deque container ----------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_ODEQUE_H__
#define __OBLIVIOUS_ODEQUE_H__

#include "O.h"
#include "omemory.h"
#include <deque>

namespace oblivious {

template <typename T, AllocatorCategory C = AllocatorCategory::PageAllocator>
using odeque = std::deque<T, oallocator<T, C>>;

} // end namespace oblivious

#endif
