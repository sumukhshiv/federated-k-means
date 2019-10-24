//===----------------------- SE.h - The SE template -----------------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __SE_H__
#define __SE_H__

#include "Covert.h"

#ifdef __clang__
#define SECRET __attribute__((annotate("secret")))
#else
#define SECRET
#endif

namespace covert {

/**
 * \defgroup LIBCOVERT_SE SE
 * \ingroup LIBCOVERT
 * \brief The SEcure template for static information flow analysis.
 *
 * The SE template uses a simple Lattice defined over two security labels:
 * ```
 *     H
 *     |
 *     L
 * ```
 * Data labeled as `L` is considered public, or non-secret, and has no
 * constraints on how it may be used. Data labeled as `H` is considered secret,
 * and may not be used in a manner which could expose a side channel, e.g. by
 * influencing a branching condition.
 *
 * Examples demonstrating the use of the SE template may be found in the
 * [tutorial](docs/Tutorial.md).
 *
 * The se namespace also exports the following functions:
 * - se_to_primitive()
 * - se_guard()
 * - se_label_cast()
 * - se_static_cast()
 * - se_reinterpret_cast()
 * - se_const_cast()
 * - se_dynamic_cast()
 *
 * More information on these functions can be found in the
 * [language reference](docs/LanguageReference.md).
 *
 * **NOTE**: By default, SE.h makes the covert::se namespace visible, e.g. via
 * \code
 * using namespace covert::se;
 * \endcode
 * This makes client code less verbose, and makes
 * refactoring easier. To disable this behavior, compile your code with the
 * `NUSE_COVERT_SE_NAMESPACE` preprocessor definition.
 *
 * @{
 */

namespace se {

/**
 * \brief The type of security labels, either `H`(igh) or `L`(ow).
 */
enum SLabel { L = 0, H = 1 };

/**
 * \brief The SEcure template.
 *
 * The SE template is an alias for covert::Covert template defined over the
 * SLabel Lattice.
 */
template <typename DataT, SLabel... Labels>
using SE = covert::Covert<SLabel, DataT, Labels...>;

GENERATE_COVERT_FUNCTIONS(se, SLabel);

} // end namespace se

/**
 * @}
 */

/**
 * \ingroup LIBCOVERT_SE
 */
template <> struct Lattice<se::SLabel> {
  using __label_type = se::SLabel;
  static constexpr __label_type bottom = se::L;
  static constexpr bool leq(__label_type l1, __label_type l2) {
    return l1 <= l2;
  }
  static constexpr __label_type join(__label_type l1, __label_type l2) {
    return (__label_type)(l1 | l2);
  }
};

#ifdef __LOG_COVERT_CPP__
namespace __covert_logging__ {

template <se::SLabel _L, se::SLabel... _Ls>
struct LabelPrinter<se::SLabel, _L, _Ls...> {
  static std::ostream &print_labels(std::ostream &out) {
    static const char label[] = {'L', 'H'};
    return ((out << label[_L]) << ... << (std::string(", ") + label[_Ls]));
  }
};
template <typename _T, se::SLabel... _Ls>
struct TypePrinter_<se::SE<_T, _Ls...>> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "SE<" << TypePrinter_cv<_T>::print_type << ", "
               << LabelPrinter<se::SLabel, _Ls...>::print_labels << ">";
  }
};

} // namespace __covert_logging__
#endif

} // namespace covert

#ifndef NUSE_COVERT_SE_NAMESPACE
using namespace covert::se;
#endif

#endif
