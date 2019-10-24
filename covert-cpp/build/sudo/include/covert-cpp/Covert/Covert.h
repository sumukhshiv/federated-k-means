//===------------------- Covert.h - The Covert template -------------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COVERT_H__
#define __COVERT_H__

/**
 * \defgroup LIBCOVERT Covert C++ Library
 * \brief The Covert C++ header files
 *
 * The Covert C++ library is implemented as a CMake interface library. You can
 * read more about CMake interface libraries here:
 *
 * https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html#interface-libraries
 *
 * If you're using CMake, you can include the Covert C++ library into a target
 * simply by invoking:
 * \code
 * target_link_libraries(<target> Covert)
 * \endcode
 *
 * All public Covert C++ definitions exist in the #covert namespace, except for
 * the SE definitions, which exist in the #covert::se namespace.
 */

/** \ingroup LIBCOVERT */
namespace covert {

/**
 * \defgroup LIBCOVERT_COVERT Covert
 * \ingroup LIBCOVERT
 * \brief The Covert template and related interfaces
 *
 * The Covert template is the bread and butter of Covert C++. It can be used
 * to associate program data with labels which characterize the confidentiality
 * of that data. These labels must form a lattice. By default, arithmetic types
 * and pointer types can be assigned labels using the Covert template. To
 * register a new type (e.g. a particular class) with the Covert C++ type
 * system, specialize the type_depth template with that type. To introduce a new
 * lattice to solve a particular confidentiality problem, specialize the Lattice
 * template with the type of the lattice elements (the labels). Then use the
 * GENERATE_COVERT_FUNCTIONS macro to generate typecasting functions for Covert
 * types specialized by the new labels. The covert_traits template provides an
 * interface for accessing attributes of a given Covert type.
 * @{
 */

/**
 * \brief The Covert template
 *
 * \details
 * The Covert template is a wrapper which associates a value with a sequence of
 * labels characterizing the confidentiality of that value. These labels must
 * form a join-semilattice (see: Lattice). When two values are arithmetically
 * or logically combined, the label of the result is the join of the labels of
 * the two operands. The type system prevents confidential data from leaking
 * through side channels, such as flow-of-control or execution time. More
 * details about the Covert C++ type system can be found in the
 * [language reference](docs/LanguageReference.md).
 *
 * \tparam LabelT the type of the label. Must specialize Lattice
 * \tparam DataT the data type. Must specialize type_depth
 * \tparam Label the label associated with this value
 * \tparam Labels the additional labels associated with this value, if
 *         `type_depth_v<DataT>` is greater than 1
 */
template <typename LabelT, typename DataT, LabelT Label, LabelT... Labels>
struct Covert;

/**
 * \brief Interface for Covert types
 *
 * \details
 * **Member types**
 * | Member name        | Description                                         |
 * | ------------------ | --------------------------------------------------- |
 * | \c label_type      | The \c LabelT parameter                             |
 * | \c value_type      | The \c DataT parameter*                             |
 * | \c reference       | `value_type &`                                      |
 * | \c const_reference | `const value_type &`                                |
 * | \c labels          | A list of all parameter labels `{Label, Labels...}` |
 *
 * *If \p CovertT is cv-qualified then \c value_type will retain those cv
 * qualifiers. If \p CovertT is an l/r-value reference, then \c value_type will
 * be an l/r-value reference.
 *
 * **Member values**
 * | Member name        | Description                                         |
 * | ------------------ | --------------------------------------------------- |
 * | \c label           | The \c Label parameter                              |
 * | \c num_labels      | The size of \c labels                               |
 *
 * \tparam CovertT must be (possibly cv-qualified, possibly reference to) a
 * Covert type
 */
template <typename CovertT> struct covert_traits;

/**
 * \brief Used by Covert operations to propagate confidentiality information
 * and enforce security constraints.
 *
 * \details A Lattice specialization provides definitions which characterize
 * a join-semilattice, bounded by a unique bottom:
 * ```C++
 * template <> struct Lattice<Label> {
 *   static constexpr Label bottom = ...;
 *   static constexpr bool leq(Label l1, Label l2) { ... }
 *   static constexpr Label join(Label l1, Label l2) { ... }
 * };
 * ```
 * For instance, we can capture the lattice
 * ```
 *    Top
 *   /   \
 * Left  Right
 *   \   /
 *   Bottom
 * ```
 * via:
 * ```C++
 * enum Simple {
 *   Bottom = 0,
 *   Left = 1 << 0,
 *   Right = 1 << 1,
 *   Top = Left | Right
 * };
 *
 * template <> struct Lattice<Simple> {
 *   static constexpr Simple bottom = Simple::Bottom;
 *   static constexpr bool leq(Simple l1, Simple l2) {
 *     return (join(l1, l2) == l2);
 *   static constexpr Simple join(Simple l1, Simple l2) {
 *     return l1 | l2;
 *   }
 * };
 * ```
 *
 * \tparam LabelT the type over which the lattice is being defined
 */
template <typename LabelT> struct Lattice;

/**
 * \brief Defines the number of labels to associate with a data type.
 *
 * \details All arithmetic types and pointer types specialize type_depth. Other
 * data types can be added to Covert C++ by specializing type_depth. For
 * instance,
 * ```C++
 * using ListIt = std::list<int>::iterator;
 * namespace covert {
 *   template <> struct type_depth<ListIt> {
 *     static constexpr unsigned value = 1;
 *   };
 * } // end namespace covert
 * ```
 * Then we can use `ListIt` as a Covert C++ data type:
 * ```C++
 * SE<ListIt, L> lowI;
 * SE<ListIt, H> highI;
 * *lowI; // allowed
 * *highI; // compiler error!
 * ```
 */
template <typename DataT> struct type_depth;
template <typename DataT>
constexpr unsigned type_depth_v = type_depth<DataT>::value;

/**
 * @}
 */

} // end namespace covert

/**
 * \ingroup LIBCOVERT_COVERT
 * \brief Generates typecasting and guard functions
 *
 * \details Invoking `GENERATE_COVERT_FUNCTIONS(pfx, LabelT)` generates
 * definitions for the following functions:
 * | Name                   | Description                                      |
 * | ---------------------- | ------------------------------------------------ |
 * | `pfx_to_primitive`     | Cast `Covert<LabelT, Labels...>` --> `LabelT`    |
 * | `pfx_guard`            | Place a constraint on the argument's label       |
 * | `pfx_label_cast`       | Cast to a Covert type with different labels      |
 * | `pfx_static_cast`      | `static_cast`, but for `Covert<LabelT, ...>`     |
 * | `pfx_reinterpret_cast` | `reinterpret_cast`, but for `Covert<LabelT, ...>`|
 * | `pfx_const_cast`       | `const_cast`, but for `Covert<LabelT, ...>`      |
 * | `pfx_dynamic_cast`     | `dynamic_cast`, but for `Covert<LabelT, ...>`    |
 *
 * More details about these functions can be found in the
 * [language reference](docs/LanguageReference.md).
 *
 * \param prefix identifier prefix for the generated functions, must be greater
 *        than zero length
 * \param label the type of the confidentiality labels for the generated
 *        functions
 */
#define GENERATE_COVERT_FUNCTIONS(prefix, label)                               \
  __GENERATE_COVERT_FUNCTIONS__(prefix, label)

#include "__covert_logging.h"
#include "__covert_helpers.h"
#include "__covert_impl.h"
#include "__covert_functions.h"

#endif
