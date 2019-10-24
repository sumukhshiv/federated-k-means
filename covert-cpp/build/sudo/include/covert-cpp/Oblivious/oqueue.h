//===---------------- oqueue.h - Oblivious queue container ----------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OQUEUE_H__
#define __OBLIVIOUS_OQUEUE_H__

#include "O.h"
#include "omemory.h"
#include "odeque.h"
#include <queue>

namespace oblivious {

template <typename T, AllocatorCateogry C = typename odeque<T>::allocator_type>
using oqueue = std::queue<T, odeque<T, C>>;

} // end namespace oblivious

#endif
