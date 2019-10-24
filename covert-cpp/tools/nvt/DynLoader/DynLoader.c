//===-------- DynLoader.c - Loads NVT test modules and runs tests ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/**
 * \defgroup NVT_DYNLOADER Dynamic Loader
 * \ingroup NVT
 * \brief Loads NVT test modules.
 *
 * The NVT dynamic loader serves two purposes:
 * 1. Loads and executes a given NVT test module
 * 2. Provides hooks to the NVT so that the NVT can init/start/end tests
 *
 * In more detail, the NVT dynamic loader loads the given test module, and
 * iteratively searches for NVT tests, named NVT_TEST_INIT(*) and
 * NVT_TEST_BEGIN(*), where * is an integer between 1 and 256. Each test must
 * define both an init and a begin function. The NVT dynamic loader then
 * sequentially executes each test that it found.
 *
 * For more details, see \ref NVT_TEST.
 * @{
 */
#include "NVT/NVTCommon.h"
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(x)                                                              \
  if (!(x)) {                                                                  \
    fprintf(stderr, __FILE__ ":%d: Assertion failed '" #x "'\n", __LINE__);    \
    exit(-1);                                                                  \
  }
#define PROGRAM_NAME "DynLoader"
#define PREFIX PROGRAM_NAME ": "

static test_init_t test_init;
static test_begin_t test_begin;

/// NVT dynamic loader runtime options.
typedef struct {
  bool Debug;             ///< Print the fuzzed input data to \c stderr
  const char *ModulePath; ///< File path for target test module
} dl_opts_t;

static dl_opts_t opts = {
    .Debug = false,
    .ModulePath = NULL,
};

void NVT_TEST_END(void) {
  asm(""); // helps to prevent inlining
}

void NVT_FUZZ_TARGET(uint8_t *data, unsigned size) {
  ASSERT(data && size > 0);
  if (opts.Debug) {
    for (uint8_t *I = data, *const E = data + size; I != E; ++I) {
      fprintf(stderr, "%02x ", *I);
    }
    fprintf(stderr, "\n");
  }

  test_init(data, size);
  test_begin();
  NVT_TEST_END();
}

/// Parse the command-line arguments.
int parse_args(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, PREFIX "expect at least one argument\n");
    return 1;
  }

  for (char **I = argv, **const E = argv + argc; I != E; ++I) {
    if (!strncmp(*I, "-d", sizeof("-d"))) {
      opts.Debug = true;
    } else if (I + 1 == E) {
      // last arg is always the module
      opts.ModulePath = *I;
    }
  }

  return 0;
}

/// \brief Runs the tests.
///
/// Performs three tasks:
/// 1. Attempt to open the given NVT test module.
/// 2. Find all tests exported by this NVT test module.
/// 3. Execute all tests in sequence.
int dl_main(void) {
  char test_init_str[32] = TO_STRING(__NVT_TEST_INIT__);
  char test_begin_str[32] = TO_STRING(__NVT_TEST_BEGIN__);
  char *const test_init_str_suffix =
      test_init_str + sizeof(TO_STRING(__NVT_TEST_INIT__)) - 1;
  char *const test_begin_str_suffix =
      test_begin_str + sizeof(TO_STRING(__NVT_TEST_BEGIN__)) - 1;

  /* Attempt to open the given NVT test module */
  void *test_module = dlopen(opts.ModulePath, RTLD_NOW);
  if (!test_module) {
    fprintf(stderr, PREFIX "could not open module '%s'\n", opts.ModulePath);
    return 2;
  }

  /* Find all tests exported by this NVT test module */
  bool found_a_test = false;
  for (int i = 1; i <= NVT_MAX_NUM_TESTS; ++i) {
    sprintf(test_init_str_suffix, "%d", i);
    sprintf(test_begin_str_suffix, "%d", i);
    test_init = dlsym(test_module, test_init_str);
    test_begin = dlsym(test_module, test_begin_str);

    /* Don't register a test unless it exported both an init() and a begin()
     * function */
    if (test_init && test_begin) {
      found_a_test = true;
      /* The NVT will catch this hook and begin fuzzing */
      NVT_FUZZ_TARGET(0, 0);
    }
  }

  if (!found_a_test) {
    fprintf(stderr, PREFIX "could not find any tests to run\n");
    dlclose(test_module);
    return 3;
  }

  dlclose(test_module);
  return 0;
}

/** @} */

int main(int argc, char **argv) {
  int err = parse_args(argc, argv);
  if (err) {
    return err;
  }

  return dl_main();
}
