#ifndef __MPC_LATTICE_H__
#define __MPC_LATTICE_H__

#include "Covert/Covert.h"

enum MPCLabel {
  Public = 0,
  Alice = 1 << 0,
  Bob = 1 << 1,
  Charlie = 1 << 2,
  AliceBob = Alice | Bob,
  AliceCharlie = Alice | Charlie,
  BobCharlie = Bob | Charlie,
  Everyone = Alice | Bob | Charlie
};

template <typename _T, MPCLabel... _Ls>
using MPC = covert::Covert<MPCLabel, _T, _Ls...>;

namespace covert {

template <> struct Lattice<MPCLabel> {
  static constexpr MPCLabel bottom = Public;
  static constexpr bool leq(MPCLabel l1, MPCLabel l2) {
    return join(l1, l2) == l2;
  }
  static constexpr MPCLabel join(MPCLabel l1, MPCLabel l2) {
    return static_cast<MPCLabel>(l1 | l2);
  }
};

#ifdef __LOG_COVERT_CPP__
namespace __covert_logging__ {

template <MPCLabel _L, MPCLabel... _Ls>
struct LabelPrinter<MPCLabel, _L, _Ls...> {
  static std::ostream &print_labels(std::ostream &out) {
    static const char *label[] = {"Public",     "Alice",   "Bob",
                                  "AliceBob",   "Charlie", "AliceCharlie",
                                  "BobCharlie", "Everyone"};
    return ((out << label[_L]) << ... << (std::string(", ") + label[_Ls]));
  }
};
template <typename _T, MPCLabel... _Ls> struct TypePrinter_<MPC<_T, _Ls...>> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "MPC<" << TypePrinter_cv<_T>::print_type << ", "
               << LabelPrinter<MPCLabel, _Ls...>::print_labels << ">";
  }
};

} // namespace __covert_logging__
#endif

} // namespace covert

GENERATE_COVERT_FUNCTIONS(mpc, MPCLabel);

#endif
