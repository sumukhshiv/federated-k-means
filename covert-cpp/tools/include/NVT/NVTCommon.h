//===---------------- NVTCommon.h - NVT common definitions ----------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __NVT_COMMON_H__
#define __NVT_COMMON_H__

#include "NVT.h"

#define TO_STRINGX(s) #s
#define TO_STRING(s) TO_STRINGX(s)

/// Exported symbol which marks the end of a test.
#define NVT_TEST_END NVT_test_end

/// Exported symbol which tells the fuzzer where to inject data.
#define NVT_FUZZ_TARGET NVT_fuzz_target

/// The maximum number of tests per test module.
#define NVT_MAX_NUM_TESTS 256

typedef void (*test_init_t)(unsigned char *data, unsigned size);
typedef void (*test_begin_t)(void);
typedef void (*test_end_t)(void);

#endif
