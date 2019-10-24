//===-------- examples/knn/covert_knn.cpp - kNN using Covert C++ ----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "knn.h"
#include "cov_algorithm.h"
#include "SE.h"
#include "ovector.h"
#include <cmath>

using namespace oblivious;

/**
 * \ingroup EXAMPLES_KNN
 */
struct SE_KNN_Entry {
  SE<int, H> category;
  SE<unsigned int, L> num_attributes;
  SE<double *, L, H> attributes;
};

static_assert(sizeof(KNN_Entry) == sizeof(SE_KNN_Entry));
static_assert(alignof(KNN_Entry) == alignof(SE_KNN_Entry));

/**
 * \ingroup EXAMPLES_KNN
 * \brief Implementation of *k*-NN with Covert C++ and libOblivious.
 */
static void classify_entry_covert(SE<unsigned, L> k,
                                  SE<unsigned, L> num_categories,
                                  SE<SE_KNN_Entry *, L> entry,
                                  SE<const SE_KNN_Entry *, L> training_set,
                                  SE<unsigned int, L> training_set_size) {
  struct pair {
    SE<const SE_KNN_Entry *, L> entry;
    SE<double, H> distance;
  };

  auto euclidean_distance = [](auto x, auto y, SE<std::size_t, L> len) {
    auto distance = (x[0] - y[0]) * (x[0] - y[0]);
    for (SE<std::size_t, L> i = 1; i < len; ++i) {
      distance += (x[i] - y[i]) * (x[i] - y[i]);
    }
    return std::sqrt(se_to_primitive(
        distance)); // safe on x86; it uses the vsqrtsd instruction
  };

  const auto neighbors = new pair[training_set_size];
  for (unsigned int i = 0; i < training_set_size; ++i) {
    neighbors[i] = {training_set + i,
                    euclidean_distance(training_set[i].attributes,
                                       entry->attributes,
                                       entry->num_attributes)};
  }
  auto cmp = [](const pair &p1, const pair &p2) {
    return p1.distance < p2.distance;
  };
  covert::sort(se_static_cast<pair *, L>(neighbors),
               neighbors + training_set_size, cmp);

  //! [covert_count]
  using HVector = oblivious::ovector<SE<unsigned, H>>;
  using HVectorIt = typename HVector::iterator;
  HVector class_votes(num_categories);
  const SE<O<HVectorIt, HVector>, L> optr{class_votes.begin(), &class_votes};
  for (SE<std::size_t, L> i = 0; i < k; ++i) {
    auto category = neighbors[i].entry->category;
    optr[category] = optr[category] + 1;
  }
  //! [covert_count]
  //! [covert_max_element]
  entry->category = covert::max_element(class_votes.begin(), class_votes.end(),
                                        &class_votes) -
                    optr;
  //! [covert_max_element]

  delete[] neighbors;
}

void knn(unsigned k, unsigned num_categories, const KNN_Entry_t *training_set,
         unsigned int training_set_size, KNN_Entry_t *test_set,
         unsigned int test_set_size) {
  for (SE_KNN_Entry *I = (SE_KNN_Entry *)test_set, *const E = I + test_set_size;
       I != E; ++I) {
    classify_entry_covert(k, num_categories, I, (SE_KNN_Entry *)training_set,
                          training_set_size);
  }
}
