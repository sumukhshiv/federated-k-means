//===------------- NVTOptions.h - Parses command-line options -------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __NVT_OPTIONS__
#define __NVT_OPTIONS__

/// \ingroup NVT_CLIENT
typedef struct {
  unsigned mask_bits;
  unsigned fuzz_iterations;
  unsigned fuzz_arg_size;
  unsigned heap_size;
  const char *log_file;
  int fuzz_cmd_argc;
  const char **fuzz_cmd_argv;
  bool expect_fail;
  bool blocks_only;
  bool software_adversary;
} nvt_options_t;

#ifdef __cplusplus
extern "C" {
#endif
void parse_options(nvt_options_t *opts, int argc, const char *argv[]);
#ifdef __cplusplus
}
#endif

#endif
