//===---------- CovertSTL.h - STL helpers for the Covert template ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef COVERT_STL_H
#define COVERT_STL_H

#include <functional>
#include <Covert.h>

namespace std {

/*******************************************************************************
 * STL Helpers
 ******************************************************************************/

template <typename T, covert::SLevel S, covert::SLevel... Ss>
struct hash<covert::SE<T, S, Ss...>> {
  using argument_type = covert::SE<T, S, Ss...>;
  using result_type = covert::SE<std::size_t, S>;
  result_type operator()(const argument_type &x) const {
    return hash<T>()(covert::declassify(x));
  }
};

} // end namespace std

#endif
