//===--------- examples/memcmp/memcmp.cpp - Covert C++ memcmp() -----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "memcmp.h"
#include <iostream>
#include "cov_algorithm.h"

/**
 * \ingroup EXAMPLES_MEMCMP
 * \brief This Covert C++ `memcmp` implementation is performance-optimized for
 * low (non-secret) inputs.
 */
SE<int, L> memcmp(SE<const uint8_t *, L, L> s1, SE<const uint8_t *, L, L> s2,
                  SE<std::size_t, L> n) {
#ifndef __NO_OUTPUT__
  std::cout << "Call to optimized memcmp()\n";
#endif
  while (n--) {
    SE<int, L> diff = *s1++ - *s2++;
    if (diff) {
      return diff;
    }
  }
  return 0;
}

/**
 * \ingroup EXAMPLES_MEMCMP
 * \brief This Covert C++ `memcmp` implementation does not leak the contents of
 * the high buffer argumens, at the cost of performance.
 */
SE<int, H> memcmp(SE<const uint8_t *, L, H> s1, SE<const uint8_t *, L, H> s2,
                  SE<std::size_t, L> n) {
#ifndef __NO_OUTPUT__
  std::cout << "Call to secure memcmp()\n";
#endif
  SE<int, H> ret = 0;
  while (n--) {
    SE<int, H> diff = *s1++ - *s2++;
    ret = covert::ternary(diff != 0 & ret == 0, diff, ret);
  }
  return ret;
}
