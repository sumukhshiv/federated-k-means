//===---------- examples/memcmp/memcmp.h - Covert C++ memcmp() ------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef MEMCMP_H
#define MEMCMP_H

#include "SE.h"
#include <cstdint>

// optimized memcmp
SE<int, L> memcmp(SE<const uint8_t *, L, L> s1, SE<const uint8_t *, L, L> s2,
                   SE<std::size_t, L> n);

// secure memcmp
SE<int, H> memcmp(SE<const uint8_t *, L, H> s1, SE<const uint8_t *, L, H> s2,
                   SE<std::size_t, L> n);

#endif
