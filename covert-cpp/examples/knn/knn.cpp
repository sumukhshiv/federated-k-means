//===-------- examples/knn/knn.cpp - A sample kNN implementation ----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "knn.h"
#include <algorithm>
#include <vector>
#include <cmath>

/**
 * \ingroup EXAMPLES_KNN
 * \brief Vanilla C++ implementation of *k*-NN.
 */
static void classify_entry(unsigned k, unsigned num_categories,
                           KNN_Entry_t *entry, const KNN_Entry_t *training_set,
                           unsigned int training_set_size) {
  struct pair {
    const KNN_Entry_t *entry;
    double distance;
  };

  //! [euclid]
  auto euclidean_distance = [](auto x, auto y, std::size_t len) {
    double distance = 0;
    for (int i = 0; i < len; ++i) {
      distance += (x[i] - y[i]) * (x[i] - y[i]);
    }
    return std::sqrt(distance);
  };
  //! [euclid]

  //! [sort]
  pair *neighbors = new pair[training_set_size];
  for (unsigned int i = 0; i < training_set_size; ++i) {
    neighbors[i] = {training_set + i,
                    euclidean_distance(training_set[i].attributes,
                                       entry->attributes,
                                       entry->num_attributes)};
  }
  auto cmp = [](const pair &p1, const pair &p2) {
    return p1.distance < p2.distance;
  };
  std::sort(neighbors, neighbors + training_set_size, cmp);
  //! [sort]

  //! [classify]
  std::vector<int> class_votes(num_categories);
  for (std::size_t i = 0; i < k; ++i) {
    int category = neighbors[i].entry->category;
    class_votes[category] = class_votes[category] + 1;
  }
  entry->category = static_cast<int>(
      std::max_element(class_votes.begin(), class_votes.end()) -
      class_votes.begin());
  //! [classify]

  delete[] neighbors;
}

void knn(unsigned k, unsigned num_categories, const KNN_Entry_t *training_set,
         unsigned int training_set_size, KNN_Entry_t *test_set,
         unsigned int test_set_size) {
  for (KNN_Entry_t *I = test_set, *const E = I + test_set_size; I != E; ++I) {
    classify_entry(k, num_categories, I, training_set, training_set_size);
  }
}
