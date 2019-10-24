//===----- examples/knn/knn.h - An example use of Covert C++ for kNN ------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __KNN_H__
#define __KNN_H__

#if defined _WIN32 || defined __CYGWIN__
#if defined(__GNUC__) || defined(__GNUG__)
#define EXPORT __attribute__((dllexport))
#else
#define EXPORT __declspec(dllexport)
#endif
#else
#if __GNUC__ >= 4
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif
#endif

/**
 * \defgroup EXAMPLES_KNN *k*-Nearest Neighbors Algorithm (*k*-NN)
 * \ingroup EXAMPLES
 * \brief A *k*-nearest neighbors algorithm (*k*-NN) example.
 *
 * This example demonstrates the application of libOblivious and Covert C++ to
 * the popular machine learning algorithm *k*-nearest neighbors (*k*-NN).
 *
 * **Note:** To run the examples in this module, you will need Python 3 and the
 * CFFI module:
 * ```
 * $ pip3 install --user cffi
 * ```
 *
 * Algorithm Description
 * ---------------------
 *
 * *k*-NN is a non-parametric classification algorithm. The program inputs
 * consist of a training set and a test set. Each set has a series of data
 * points, each of which has a sequence of attributes. A generic implementation
 * of *k*-NN would also accept a measure of distance as a parameter. For
 * simplicity, this example assumes that all attributes can be represented as a
 * `double`, and it uses Euclidian distance to measure the proximity of data
 * points to one another. For each data point *p* in the test set, *k*-NN finds
 * its *k* nearest "neighbors" in the training set (using the distance metric).
 * The class assigned to *p* by *k*-NN is the mode of the classes of its *k*
 * nearest neighbors. If the neighbors have no mode (e.g. two classes are
 * equally represented among the *k* neighbors), then *k*-NN must use some
 * heuristic (e.g. randomness) to choose the class for *p*. More details on
 * *k*-NN can be found
 * [here](https://en.wikipedia.org/wiki/K-nearest_neighbors_algorithm).
 *
 * The classify_entry() function in knn.cpp is a vanilla C++ implementation of
 * a *k*-NN classifier. For simplicity, we use the Euclidean distance metric:
 *
 * \snippetlineno knn/knn.cpp euclid
 *
 * For the given data point *p* in the test set, its proximity to each data
 * point in the training set is computed and recorded in an array. Then the
 * array is sorted in increasing order of proximity. Thus the first *k* data
 * points in the sorted array are the *k* nearest neighbors of *p*.
 *
 * \snippetlineno knn/knn.cpp sort
 *
 * The final step is to classify *p* based on a majority vote of its *k*
 * nearest neighbors. Note that we use the word "category" in the
 * implementation instead of "class". This is because "class" is a keyword in
 * C++.
 *
 * \snippetlineno knn/knn.cpp classify
 *
 * *Note*: This implementation of *k*-NN is actually biased towards categories
 * with lower class identifiers. This is because when `std::%max_element()`
 * is applied to a container wherein several elements are equal to the greatest
 * element, an iterator to the first such element is returned.
 *
 * This example can be run by building the `example-knn-run` target.
 *
 * k-NN with libOblivious
 * ------------------------
 *
 * The classify_entry_oblivious() function in knn_oblivious.cpp performs the
 * same computation as classify_entry(), except that it uses primitives and
 * algorithms from \ref OBLIVIOUS to prevent the attributes and categories of
 * the input set and test set from leaking through a side channel. To
 * ensure this, all flow-of-control patterns and memory-access patterns which
 * depend on input categories and attributes must be obfuscated. There are
 * three places in our implementation of *k*-NN where this can happen.
 *
 * First, the training set data points are sorted by their proximity to the
 * current test set data point. The proximity was computed using the data point
 * attributes; these must not be leaked. The C++ STL's `std::%sort()` algorithm
 * is not oblivious, hence it may leak information about the values in the
 * container being sorted. libOblivious provides the oblivious::osort()
 * function to obliviously sort data. classify_entry_oblivious() uses this
 * instead of `std::%sort()`:
 *
 * \snippetlineno knn/oblivious_knn.cpp osort
 *
 * Second, tallying the "votes" for each class can also leak information. To
 * count the votes, we use a direct address table (implemented as a vector)
 * indexed by class, e.g. 0, 1, 2, 3, etc. Whenever one of the *k* nearest
 * neighbors votes for its class, that class's entry is incremented in the
 * table. This increment operation--a read followed by a write--may leak the
 * address in memory where the value is being updated. To perform this update
 * obliviously, we use the oblivious::O primitive from libOblivious. O is a
 * wrapper around an iterator which performs memory accesses obliviously:
 *
 * \snippetlineno knn/oblivious_knn.cpp ocount
 *
 * A subscript `operator[]()` access on an O iterator will not leak the value
 * of the subscript argument, nor will it leak the value of the iterator
 * itself.
 *
 * Third, just as `std::%sort()` was not oblivious, `std::%max_element()` is
 * also not oblivious. libOblivious also provides a solution:
 *
 * \snippetlineno knn/oblivious_knn.cpp omax_element
 *
 * This example can be run by building the `example-oblivious-knn-run` target.
 *
 * k-NN with Covert C++
 * --------------------
 *
 * One issue with libOblivious is that it isn't always clear when it should or
 * should not be used. For instance, our *k*-NN example only assumes that the
 * data attributes and classes need to be kept confidential (i.e. must not be
 * leaked). Using libOblivious to obfuscate any other values would likely slow
 * down the program, without adding any security. Conversely, failing to
 * identify a potential leak of confidential data and patching it with
 * libOblivious could expose that confidential data through a side channel. The
 * solution is to use Covert C++ to identify confidential inputs and trace
 * their propagation through the program.
 *
 * The classify_entry_covert() function uses Covert C++ and libOblivious
 * together to provide assurance that the confidentiality of secret inputs is
 * preserved. First, the function inputs are all labeled:
 * \code
 * static void
 * classify_entry_covert(SE<unsigned, L> k,
 *                       SE<unsigned, L> num_categories,
 *                       SE<SE_KNN_Entry *, L> entry,
 *                       SE<const SE_KNN_Entry *, L> training_set,
 *                       SE<unsigned int, L> training_set_size);
 * \endcode
 * That is, `k`, `num_categories`, and `training_set_size` are not confidential
 * because they have been assigned the low (`L`) label. Also, the pointer to
 * the entry to be categorized, and the pointer to the training set are not
 * confidential. The data which is confidential is every
 * SE_KNN_Entry::category and the pointee(s) of every SE_KNN_Entry::attributes.
 *
 * With the use of the C++ `auto` keyword to trigger type inference, the
 * implementation does not need to change a whole lot. Covert C++ allows type
 * inference to automatically propagate security labels through a program, and
 * type errors will occur wherever confidential data may leak through a side
 * channel. Calling `std::%sort()` or oblivious::osort() over a container with
 * data labeled `H` will fail to type check. Instead, Covert C++ provides
 * covert::sort(), which uses uses the types and labels of the given arguments
 * to determine whether the contents of the container to be sorted are
 * confidential. If so, it will call oblivious::osort(); otherwise it will call
 * the optimized `std::%sort()`.
 *
 * The most substantial differences from the previous example arise in the vote
 * counting:
 *
 * \snippetlineno knn/covert_knn.cpp covert_count
 *
 * First, note that the contents of the `class_votes` vector have been manually
 * labeled `H`. What if the developer had instead marked them `L`? Then a type
 * error would have been indicated several lines later:
 * ```
 * knn/covert_knn.cpp:61:20: error: no viable overloaded '='
 *  optr[category] = optr[category] + 1;
 *  ~~~~~~~~~~~~~~ ^ ~~~~~~~~~~~~~~~~~~
 *
 * include/Covert/__covert_o_impl.h:85:15: note:
 *  candidate template ignored: requirement
 *    'Lattice<se::SLabel>::leq(__accessor_label, __iterator_value_type_label)'
 *    was not satisfied
 * ```
 * The `SE<O<...>, ...>` iterator wrapper requires that data being written to
 * its contents must have a security label less than or equal to the label of
 * its contents. Similarly, the security label of the subscript argument must
 * also be less than or equal to the security label of the contents. The
 * inferred type of the `category` variable is `SE<unsigned, H>`. Since `H` is
 * not less than or equal to `L`, this write should not be allowed. Indeed,
 * Covert C++ caught the potential vulnerability.
 *
 * Finally, similar to covert::sort(), Covert C++ provides a safe alternative
 * to `std::%max_element()`, covert::max_element():
 *
 * \snippetlineno knn/covert_knn.cpp covert_max_element
 *
 * This example can be run by building the `example-covert-knn-run` target.
 *
 * Validating the k-NN Examples using the NVT
 * ------------------------------------------
 *
 * If your platform is supported by the NVT, you can test each of the three
 * implementations of *k*-NN by building the following targets:
 * - `example-knn-test`
 * - `example-oblivious-knn-test`
 * - `example-covert-knn-test`
 *
 * These tests all use the NVT test module defined in knn_test.c. For a
 * tutorial on writing NVT modules, see the \ref EXAMPLES_MEMCMP_NVT module.
 * Documentation on NVT usage can be found [here](docs/NVT.md). The NVT
 * implementation documentation can be found in the \ref NVT module.
 */

/**
 * \ingroup EXAMPLES_KNN
 * \brief Assigns attributes and a class (category) to a data point.
 */
typedef struct KNN_Entry {
  int category;
  unsigned int num_attributes;
  double *attributes;
} KNN_Entry_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \ingroup EXAMPLES_KNN
 * \brief C interface to the k Nearest Neighbors (kNN) algorithm.
 *
 * The algorithm sets the KNN_Entry_t::category entries in the \p test_set to
 * the predicted values, given the \p training_set.
 */
EXPORT void knn(unsigned k, unsigned num_categories,
                const KNN_Entry_t *training_set, unsigned int training_set_size,
                KNN_Entry_t *test_set, unsigned int test_set_size);

#ifdef __cplusplus
}
#endif

#endif
