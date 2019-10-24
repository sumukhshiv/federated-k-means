//===------ oforward_list.h - Oblivious singly linked list container ------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OFORWARD_LIST_H__
#define __OBLIVIOUS_OFORWARD_LIST_H__

#include "O.h"
#include "omemory.h"
#include <forward_list>

namespace oblivious {

template <typename T, AllocatorCategory C = AllocatorCategory::PageAllocator>
using oforward_list = std::forward_list<T, oallocator<T, C>>;

} // end namespace oblivious

#endif
