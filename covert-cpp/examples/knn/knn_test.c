//===------ examples/knn/knn_test.cpp - Example showing use of NVT --------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/**
 * NOTE: This test is guaranteed to fail until support is added to the NVT for
 * heap allocation in the target application. See docs/FutureProjects.md for
 * more information
 */
#include "knn.h"
#include <NVT.h>

#undef NDEBUG
#include <assert.h>

#define NUM_CATEGORIES 4
#define ATTRIBUTES_PER_ENTRY 2
#define MAX_TEST_SIZE_IN_BYTES 4096
#define BYTES_PER_ENTRY (ATTRIBUTES_PER_ENTRY * sizeof(double) + 1)
#define MAX_ENTRIES (MAX_TEST_SIZE_IN_BYTES / BYTES_PER_ENTRY)

NVT_TEST_MODULE;

static unsigned k = 4;
static KNN_Entry_t entries[MAX_ENTRIES];
static double attributes[MAX_ENTRIES][2];
static const float ratio = 2.0 / 3.0;
static int training_set_size, test_set_size;

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  assert(size <= MAX_TEST_SIZE_IN_BYTES);
  KNN_Entry_t *entry = entries;
  int total_entries = 0;
  for (unsigned char *I = data, *const E = data + size; I + BYTES_PER_ENTRY < E;
       I += BYTES_PER_ENTRY, ++entry) {
    entry->num_attributes = ATTRIBUTES_PER_ENTRY;
    entry->attributes = attributes[entry - entries];
    for (unsigned i = 0; i < ATTRIBUTES_PER_ENTRY; ++i) {
      entry->attributes[i] = ((const double *)I)[i];
    }
    entry->category = *(I + BYTES_PER_ENTRY - 1) % NUM_CATEGORIES;
    ++total_entries;
  }
  training_set_size = total_entries * (1.0 - ratio);
  test_set_size = total_entries * ratio;
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  const KNN_Entry_t *training_set = entries;
  KNN_Entry_t *test_set = entries + training_set_size;
  knn(k, NUM_CATEGORIES, training_set, training_set_size, test_set,
      test_set_size);
}
