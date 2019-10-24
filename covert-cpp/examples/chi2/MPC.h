//===---- examples/chi2/MPC.h - An example use of Covert C++ for SMPC -----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __MPC_H__
#define __MPC_H__

/**
 * \addtogroup EXAMPLES_CHI2
 * @{
 */

/**
 * \brief Label type for the chi-squared example.
 *
 * Each principal has a corresponding bit:
 * - Alice: 0
 * - Bob: 1
 * - Charlie: 2
 * - Dylan: 3
 *
 * For instance, if only bits 1 and 3 are set, then this label may identify
 * data which was tainted by Bob and Dylan. For instance,
 * ```C++
 * MPC<int, Bob> x = 2;
 * MPC<int, Dylan> y = 40;
 * auto z = x + y; // z has type MPC<int, BobDylan>
 * ```
 */
enum MPCLabel {
  Public = 0,
  Alice = 1 << 0,
  Bob = 1 << 1,
  AliceBob = Alice | Bob,
  Charlie = 1 << 2,
  AliceCharlie = Alice | Charlie,
  BobCharlie = Bob | Charlie,
  AliceBobCharlie = Alice | Bob | Charlie,
  Dylan = 1 << 3,
  AliceDylan = Alice | Dylan,
  BobDylan = Bob | Dylan,
  CharlieDylan = Charlie | Dylan,
  AliceBobDylan = Alice | Bob | Dylan,
  AliceCharlieDylan = Alice | Charlie | Dylan,
  BobCharlieDylan = Bob | Charlie | Dylan,
  Everyone = Alice | Bob | Charlie | Dylan
};

namespace covert {

/**
 * \brief The Lattice of MPC labels.
 *
 * To join two labels, we take the bitwise or.
 * To compute `l1 <= l2`, we compute whether the join of `l1` and `l2` is equal
 * to `l2`.
 */
template <> struct Lattice<MPCLabel> {
  static constexpr MPCLabel bottom = Public;
  static constexpr bool leq(MPCLabel l1, MPCLabel l2) {
    return join(l1, l2) == l2;
  }
  static constexpr MPCLabel join(MPCLabel l1, MPCLabel l2) {
    return (MPCLabel)(l1 | l2);
  }
};

} // namespace covert

/**
 * The MPC template is an alias for covert::Covert, defined over MPCLabel.
 */
template <typename _T, MPCLabel... _Ls>
using MPC = covert::Covert<MPCLabel, _T, _Ls...>;

/**
 * @}
 */

#ifdef __LOG_COVERT_CPP__
#include "MPC_log.h"
#endif

GENERATE_COVERT_FUNCTIONS(mpc, MPCLabel);

#endif
