//===---------- olist.h - Oblivious doubly linked list container ----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OLIST_H__
#define __OBLIVIOUS_OLIST_H__

#include "O.h"
#include "omemory.h"
#include <list>

namespace oblivious {

template <typename T, AllocatorCategory C = AllocatorCategory::PageAllocator>
using olist = std::list<T, oallocator<T, C>>;

} // end namespace oblivious

#endif
