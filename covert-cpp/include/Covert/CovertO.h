//===---------- CovertO.h - Covert template specialization for O ----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COVERT_O_H__
#define __COVERT_O_H__

#include "Covert.h"
#include "__covert_o_impl.h"

namespace covert {

/**
 * \ingroup LIBCOVERT_COVERT
 * \brief The Covert template can wrap oblivious iterators.
 *
 * The Covert template can wrap oblivious iterators and provide the following
 * optimization. For a given label type `LabelT` and label `l` of type
 * `LabelT`, if `l == Lattice<LabelT>::%bottom` then reads and writes on the
 * wrapped iterator are not oblivious. Otherwise, reads and writes are
 * oblivious. This is because data with the bottom label is
 * assumed to be public, i.e. not confidential. All other data is assumed
 * non-public, and thus must be protected from implicit and explicit leakage,
 * e.g. by oblivious computation.
 */
template <typename IterT, typename ContainerT>
struct type_depth<oblivious::O<IterT, ContainerT>>
    : std::integral_constant<unsigned, 1> {};

#ifdef __LOG_COVERT_CPP__
namespace __covert_logging__ {

template <typename IterT, typename ContainerT>
struct TypePrinter_<oblivious::O<IterT, ContainerT>> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "O<" << TypePrinter_cv<IterT>::print_type << ", "
               << TypePrinter_cv<ContainerT>::print_type << ">";
  }
};

} // end namespace __covert_logging__
#endif

} // end namespace covert

#endif
