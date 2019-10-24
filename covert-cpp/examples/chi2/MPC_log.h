//===--- examples/chi2/MPC_log.h - An example use of Covert C++ for SMPC --===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

namespace covert {
namespace __covert_logging__ {

template <MPCLabel _L, MPCLabel... _Ls>
struct LabelPrinter<MPCLabel, _L, _Ls...> {
  static std::ostream &print_labels(std::ostream &out) {
    static const char *label[] = {"Public",
                                  "Alice",
                                  "Bob",
                                  "AliceBob",
                                  "Charlie",
                                  "AliceCharlie",
                                  "BobCharlie",
                                  "AliceBobCharlie",
                                  "Dylan",
                                  "AliceDylan",
                                  "BobDylan",
                                  "AliceBobDylan",
                                  "CharlieDylan",
                                  "AliceCharlieDylan",
                                  "BobCharlieDylan",
                                  "Everyone"};
    return ((out << label[_L]) << ... << (std::string(", ") + label[_Ls]));
  }
};
template <typename _T, MPCLabel... _Ls> struct TypePrinter_<MPC<_T, _Ls...>> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "MPC<" << TypePrinter_cv<_T>::print_type << ", "
               << LabelPrinter<MPCLabel, _Ls...>::print_labels << ">";
  }
};

} // end namespace __covert_logging__
} // end namespace covert
