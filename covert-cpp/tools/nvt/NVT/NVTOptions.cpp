//===------------ NVTOptions.cpp - Parses command-line options ------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/**
 * \ingroup NVT_CLIENT
 *
 * @{
 */
#include "NVTOptions.h"
#include "dr_api.h"
#include "droption.h"
#include <iostream>

#define MAX_PATH_SIZE 1024

/// \brief Cache block width (in bits)
///
/// \details Memory trace mask (in bits), used for setting NVT analysis
/// granularity. e.g. '6' for a cache line on a typical x86 CPU
/// \hideinitializer
static droption_t<unsigned> opt_mask_bits{
    DROPTION_SCOPE_CLIENT, "c", 0, "Memory trace mask (in bits)",
    "Memory trace mask (in bits), used for setting NVT analysis granularity. "
    "e.g. '6' for a cache line on a typical x86 CPU"};

/// \brief Number of iterations over which to run the fuzzer
/// \hideinitializer
static droption_t<unsigned> opt_fuzz_iterations{
    DROPTION_SCOPE_CLIENT, "n", 10000, "Fuzz iterations",
    "Number of iterations over which to run the fuzzer"};

/// \brief Size of the application heap.
/// \hideinitializer
static droption_t<unsigned> opt_heap_size{
    DROPTION_SCOPE_CLIENT, "heap-mem", 16, "Application heap memory (MB)",
    "Size of the application heap in MB"};

/// \brief Size of the data argument to NVT_TEST_INIT(*)
/// \hideinitializer
static droption_t<unsigned> opt_fuzz_arg_size{
    DROPTION_SCOPE_CLIENT, "s", 8, "Fuzz argument size",
    "Size of the data argument to NVT_TEST_INIT(*)"};

/// \brief Enable logging of memory accesses to a log file
/// \hideinitializer
static droption_t<std::string> opt_logging{
    DROPTION_SCOPE_CLIENT, "l", "", "Print log info to file",
    "Enable logging of memory accesses to a log file"};

/// \brief Arguments to the Dr.\ Fuzz extension
/// \hideinitializer
static droption_t<bool> opt_fuzz_cmd{DROPTION_SCOPE_CLIENT, "a", false,
                                     "Provide additional args to Dr. Fuzz",
                                     "Arguments to the Dr. Fuzz extension"};

/// \brief Expect a test to fail, e.g.\ by inverting the process result
/// \hideinitializer
static droption_t<bool> opt_expect_fail{
    DROPTION_SCOPE_CLIENT, "f", false, "Expect a test to fail",
    "Expect a test to fail, e.g. by inverting the process result"};

/// \brief Prints the NVT command-line usage and exits
/// \hideinitializer
static droption_t<bool> opt_help{DROPTION_SCOPE_CLIENT, "h", false,
                                 "Print usage and exit",
                                 "Prints the NVT command-line usage and exits"};

/// \brief Only analyze cache line touches
/// \hideinitializer
static droption_t<bool> opt_blocks_only{
    DROPTION_SCOPE_CLIENT, "b", false, "Only analyze cache line touches",
    "Only analyze cache line touches, logging still reports r/w/bb"};

/// \brief Use the software adversary model
///
/// An adversary who can view hardware-based side channels such as cache line
/// misses may be able to discern the order in which VSIB-addressed instructions
/// (e.g. AVX/AVX2 instructions like `vpgatherdd`) access memory. An adversary
/// who can only observe side channels through software will likely not have
/// this observation power. The `-s` flag performs the trace analysis with the
/// assumption that the adversary follows the weaker software model.
///
/// \hideinitializer
static droption_t<bool> opt_software_adversary{
    DROPTION_SCOPE_CLIENT, "s", false, "Use the software adversary model",
    "Assume that the adversary only has the means to observe side channels "
    "through software"};

/// \brief Stores the file path for the log file
static char log_file_buffer[MAX_PATH_SIZE];

void parse_options(nvt_options_t *opts, int argc, const char *argv[]) {
  /* Check for Dr. Fuzz args */
  opts->fuzz_cmd_argc = 0;
  const std::string flag = "-a";
  for (int i = 0; i < argc; ++i) {
    if (flag == *(argv + i)) {
      opts->fuzz_cmd_argv = argv + (i + 1);
      opts->fuzz_cmd_argc = argc - (i + 1);
      break;
    }
  }

  /* Use droption to parse the remaining arguments */
  std::string parse_err;
  if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT,
                                     argc - opts->fuzz_cmd_argc, argv,
                                     &parse_err, NULL)) {
    std::cerr << "Usage error: " << parse_err.c_str() << '\n';
    std::cerr << droption_parser_t::usage_short(DROPTION_SCOPE_CLIENT);
    dr_abort();
  }

  if (opt_help.get_value()) {
    std::cerr << droption_parser_t::usage_short(DROPTION_SCOPE_CLIENT);
    dr_abort();
  }

  opts->mask_bits = opt_mask_bits.get_value();
  opts->fuzz_iterations = opt_fuzz_iterations.get_value();
  opts->fuzz_arg_size = opt_fuzz_arg_size.get_value();
  opts->heap_size = opt_heap_size.get_value();
  opts->blocks_only = opt_blocks_only.get_value();
  opts->software_adversary = opt_software_adversary.get_value();
  if (opt_logging.get_value().empty()) {
    opts->log_file = NULL;
  } else {
    DR_ASSERT(opt_logging.get_value().size() <= MAX_PATH_SIZE);
    opt_logging.get_value().copy(log_file_buffer, MAX_PATH_SIZE);
    opts->log_file = log_file_buffer;
  }
  opts->expect_fail = opt_expect_fail.get_value();
}
/** @} */
