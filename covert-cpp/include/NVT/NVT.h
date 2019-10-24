//===--------------- NVT.h - #includes for NVT test modules ---------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/**
 * \defgroup NVT Noninterference Verification Tool (NVT)
 * \brief Dynamic analysis tool which can detect whether program code is
 * noninterferent.
 *
 * The NVT fuzzes secret program inputs, and detects whether these input
 * perturbations affect memory and instruction traces, and program outputs. When
 * secret inputs do affect these traces, a side-channel vulnerability may be
 * exposed to a malicious adversary.
 */

/**
 * \defgroup NVT_TEST NVT Test Module
 * \ingroup NVT
 * \brief Interface for creating NVT test modules.
 *
 * The following is a skeleton layout for an NVT test file:
 * ```
 * #include <Covert/NVT.h>
 * // other #includes for the target function(s), etc.
 *
 * NVT_TEST_MODULE; // exports a special symbol for use by the NVT
 *
 * typedef unsigned char byte;
 *
 * // Arguments for the target function(s) should be declared here. They will be
 * // initialized in the NVT_TEST_INIT(*)() functions, and used in the
 * // NVT_TEST_BEGIN(*)() functions.
 *
 * // Everything below this line is a hook function called by the DynLoader
 * extern "C" NVT_EXPORT void NVT_TEST_INIT(1)(byte *data, unsigned size) {
 *   // initialize global data structures and/or target function arguments
 * }
 * extern "C" NVT_EXPORT void NVT_TEST_BEGIN(1)() {
 *   // call the target function(s)
 * }
 *
 * extern "C" NVT_EXPORT void NVT_TEST_INIT(2)(byte *data, unsigned size) {
 *   // initialize data for another test
 * }
 * extern "C" NVT_EXPORT void NVT_TEST_BEGIN(2)(){
 *   // call the target function(s) for the second test
 * }
 * ```
 */

#ifndef __NVT_H__
#define __NVT_H__

#define __NVT_TEST_INIT__ NVT_test_init
#define __NVT_TEST_BEGIN__ NVT_test_begin
#define __NVT_TEST_MODULE__ NVT_test_module

#define __NVT_CONCATX__(x, y) x##y
#define __NVT_CONCAT__(x, y) __NVT_CONCATX__(x, y)
/// \brief Generates a name for the Nth test init in an NVT test module.
/// \ingroup NVT_TEST
#define NVT_TEST_INIT(N) __NVT_CONCAT__(__NVT_TEST_INIT__, N)
/// \brief Generates a name for the Nth test begin in an NVT test module.
/// \ingroup NVT_TEST
#define NVT_TEST_BEGIN(N) __NVT_CONCAT__(__NVT_TEST_BEGIN__, N)

/// \brief Exports a symbol so that it can be seen by the NVT Client and the
/// DynLoader.
/// \ingroup NVT_TEST
#if defined _WIN32 || defined __CYGWIN__
#if defined(__GNUC__) || defined(__GNUG__)
#define NVT_EXPORT __attribute__((dllexport))
#else
#define NVT_EXPORT __declspec(dllexport)
#endif
#else
#if __GNUC__ >= 4
#define NVT_EXPORT __attribute__((visibility("default")))
#else
#define NVT_EXPORT
#endif
#endif

/// \brief Declares that a source file defines at least one NVT test.
/// \ingroup NVT_TEST
#ifdef __cplusplus
#define NVT_TEST_MODULE                                                        \
  extern "C" NVT_EXPORT void __NVT_TEST_MODULE__(void) {}
#else
#define NVT_TEST_MODULE                                                        \
  NVT_EXPORT void __NVT_TEST_MODULE__(void) {}
#endif

#endif
