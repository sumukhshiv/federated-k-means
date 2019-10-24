//===--- examples/chi2/main.cpp - An example use of Covert C++ for SMPC ---===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Covert.h"
#include <cassert>
#include <iostream>
#include <vector>
#include <tuple>

#include "MPC.h"

using namespace covert;

/**
 * \defgroup EXAMPLES_CHI2 Chi-Squared
 * \ingroup EXAMPLES
 * \brief Covert C++ SMPC Chi-Squared Example
 *
 * This example demonstrates the application of Covert C++ to the Secure
 * Multiparty Computation (SMC) problem. The example is derived from a
 * [Wikipedia
 * article](https://en.wikipedia.org/wiki/Chi-squared_test#Example_chi-squared_test_for_categorical_data)
 * describing the computation of the chi-squared statistic for a two-dimensial
 * dataset. The dataset compares category of employment (white collar, blue
 * collar, no collar) against neighborhood. A chi-squared statistic can be used
 * to determine whether there is a significant difference between observed
 * frequencies and expected frequencies in categorical data.
 *
 * Suppose that Alice, Bob, Charlie, and Dylan live in four different
 * neighborhoods, A, B, C, and D, respectively. Each polls his/her own
 * neighborhood for employment type, and records the results:
 * |                  | A   | B   | C   | D   | total |
 * | ---------------- |:---:|:---:|:---:|:---:|:-----:|
 * | White collar     | 90  | 60  | 104 | 95  | 349   |
 * | Blue collar      | 30  | 50  | 51  | 20  | 151   |
 * | No collar        | 30  | 40  | 45  | 35  | 150   |
 * | Total            | 150 | 150 | 200 | 150 | 650   |
 *
 * We assign this data to each principal as follows:
 *
 * \snippet this data
 *
 * The four principals would like to compute the chi-squared test statistic
 * over the categorical data given in the table. However, suppose that Alice,
 * Bob, Charlie and Dylan are mutually distrusting of one another. Each
 * principal would prefer not to share his/her own input data with any other
 * principal. But any principal participating in the computation may be allowed
 * to see the ouput test statistic.
 *
 * The #MPCLabel type forms a lattice, with the `join` and `leq` operations
 * and `bottom` label defined by a specialization of the covert::Lattice
 * template class. The chi2() function is variadic, so it can accept any number
 * of arguments (but it requires at least two). The implementation of chi2()
 * makes extensive use of type inference, e.g. using the \c auto keyword. So the
 * return type of chi2() is entirely inferred by the compiler from its
 * arguments. In this case, because the data from each participant is combined
 * (e.g. when the rows of the matrix are summed), the test statistic returned
 * from chi2() will have a label equal to cumulative `join` of all of the
 * participants.
 *
 * If #Alice, #Bob, #Charlie and #Dylan all participate in the computation, the
 * setup may look like this:
 *
 * \snippet this test1
 *
 * Notice that we use the \c auto keyword to tell the compiler to infer the
 * return type for the value `result`. As explained above, the type of `result`
 * will capture all of the principals who participated in the computation. In
 * this example, the type will be `MPC<double, Everyone>`.
 *
 * Internally, the output() function in this example declassifies the result
 * by making it Public, then emits it to \c stdout. In a real-world application
 * the output() function would emit the result to each principal identified in
 * the template argument over a communicate channel, e.g. TCP/IP. So test1()
 * would send the result to each of #Alice, #Bob, #Charlie, and #Dylan, the
 * principals included in #Everyone.
 *
 * What if #Bob doesn't participate in the computation? That is, we only
 * compute `chi2(a, c, d)`. Then perhaps #Bob should not be allowed to receive
 * the output. A naive implementation would hardcode this constraint, e.g.
 * `output<AliceCharlieDylan>(...)` or `output<~Bob>(...)`. A more flexible
 * approach would be to use type inference and the covert::covert_traits
 * interface:
 *
 * \snippet this test2
 *
 * The test2() example is functionally identical to test1(), except that #Bob
 * does not participate in the computation and also does not receive the result.
 * The label of the result captures precisely the principals who do participate
 * in the computation, so we use this to direct the output accordingly. In this
 * example, only #Alice, #Charlie, and #Dylan will receive the output.
 *
 * The output() function works as expected, but it does not perform any kind of
 * validation on its inputs. For example, we might want to require that in
 * order for a value to be output to a principal's channel, that principal must
 * have participated in the computation. In test3(), we introduce a
 * guarded_output() wrapper around output(), which accepts an additional
 * boolean template parameter. If the parameter is \c false, then the compiler's
 * function overloading will not consider it as a candidate, and thus the
 * compiler will emit an error.
 *
 * \snippet this test3
 *
 * For each principal, the guard checks that he/she participated in the
 * computation by ensuring that the output channel is `leq` the label of the
 * computation result on the #MPCLabel lattice. Thus for #Bob, the guard will
 * fail.
 *
 * **Note:** The source code for this tutorial can be found in `examples/memcmp/`.
 * It can be built by making the `example-chi2-run` target.
 */

// square a value
template <typename _T> static constexpr _T square(_T val) { return val * val; }

template <typename _MatrixT, std::size_t... J>
auto chi2_impl(const _MatrixT &Obs, std::size_t rows,
               std::index_sequence<J...> cols) {
  using RetT = decltype((... + std::get<J>(Obs)[0]));

  auto SumColumn = [rows](const auto &col) -> auto {
    auto ret = col[0];
    for (int i = 1; i < rows; ++i) {
      ret += col[i];
    }
    return ret;
  };
  auto ColumnSums = std::tuple{SumColumn(std::get<J>(Obs))...};
  auto SumRow = [&Obs](std::size_t i) -> auto {
    return (... + std::get<J>(Obs)[i]);
  };
  std::vector<RetT> RowSums(rows);
  for (int i = 0; i < rows; ++i) {
    RowSums[i] = SumRow(i);
  }
  auto Total = (... + std::get<J>(ColumnSums));

  auto ExpColumn = [&](const auto &col, auto sum) -> auto {
    std::vector<RetT> exp(rows);
    for (int i = 0; i < rows; ++i) {
      exp[i] = sum * (RowSums[i] / Total);
    }
    return exp;
  };
  auto Exp =
      std::tuple{ExpColumn(std::get<J>(Obs), std::get<J>(ColumnSums))...};

  RetT ret = 0.0;
  for (int i = 0; i < rows; ++i) {
    ret += (... + ((square(std::get<J>(Obs)[i] - std::get<J>(Exp)[i])) /
                   std::get<J>(Exp)[i]));
  }
  return ret;
}

/**
 * \ingroup EXAMPLES_CHI2
 * \brief Compute the chi-squared statistic for the argument vectors.
 */
template <typename _ArgT, typename... _ArgTs>
auto chi2(const _ArgT &arr, const _ArgTs &... arrs) {
  std::size_t size = arr.size();
  assert(size > 0 && "args must be non-empty");
  assert((... && (size == arrs.size())) && "args are not all the same size");
  return chi2_impl(
      std::forward_as_tuple<const _ArgT &, const _ArgTs &...>(arr, arrs...),
      size, std::make_index_sequence<1 + sizeof...(_ArgTs)>{});
}

/**
 * \ingroup EXAMPLES_CHI2
 * \brief Output \p val to \p Principal.
 *
 * This function will not type check if
 * \code
 * Lattice<MPCLabel>::leq(covert_traits<T>::label, Principal) == false
 * \endcode
 * That is, the label of the argument \p val must be <= \p Principal.
 */
template <MPCLabel Principal, typename T> void output(const T &val) {
  using ValueT = typename covert_traits<const T &>::value_type;
  const auto &declassified = mpc_label_cast<ValueT, Public>(val);
  std::cout
      << declassified << " [channel: "
      << __covert_logging__::LabelPrinter<MPCLabel, Principal>::print_labels
      << "]" << std::endl;
}

/**
 * \ingroup EXAMPLES_CHI2
 * \brief A vector of \p T data belonging to \p Principal.
 */
template <typename T, auto Principal>
using PVec = std::vector<MPC<T, Principal>>;

//! [data]
static const PVec<double, Alice> a = {90.0, 30.0, 30.0};
static const PVec<double, Bob> b = {60.0, 50.0, 40.0};
static const PVec<double, Charlie> c = {104.0, 51.0, 45.0};
static const PVec<double, Dylan> d = {95.0, 20.0, 35.0};
//! [data]

#ifdef __LOG_COVERT_CPP__
#define LOG_TYPE(msg, type)                                                    \
  {                                                                            \
    std::cout << msg << ": "                                                   \
              << __covert_logging__::TypePrinter<type>::print_type             \
              << std::endl;                                                    \
  }
#else
#define LOG_TYPE(msg, type)
#endif

//! [test1]
void test1() {
  auto result = chi2(a, b, c, d);
  LOG_TYPE("test1 chi2 return type", decltype(result));
  std::cout << "test1 output: ";
  output<Everyone>(result);
}
//! [test1]

//! [test2]
void test2() {
  auto result = chi2(a, c, d);
  constexpr MPCLabel ResultLabel =
      covert_traits<decltype(result)>::label; // ResultLabel ==
                                              // MPCLabel::AliceCharlieDylan
  LOG_TYPE("test2 chi2 return type", decltype(result));
  std::cout << "test2 output: ";
  output<ResultLabel>(result);
}
//! [test2]

//! [test3]
template <MPCLabel Principal, bool Guard, typename T,
          typename = std::enable_if_t<Guard>>
void guarded_output(const T &val) {
  output<Principal>(val);
}

void test3() {
  auto result = chi2(a, c, d);
  constexpr MPCLabel ResultLabel =
      covert_traits<decltype(result)>::label; // ResultLabel ==
                                              // MPCLabel::AliceCharlieDylan
  using L = Lattice<MPCLabel>;
  LOG_TYPE("test3 chi2 return type", decltype(result));
  std::cout << "test3 output: \n";
  guarded_output<Alice, L::leq(Alice, ResultLabel)>(result);
  // guarded_output<Bob, L::leq(Bob, ResultLabel)>(result); <-- compiler error!
  guarded_output<Charlie, L::leq(Charlie, ResultLabel)>(result);
  guarded_output<Dylan, L::leq(Dylan, ResultLabel)>(result);
}
//! [test3]

int main() {
  test1();
  test2();
  test3();
}
