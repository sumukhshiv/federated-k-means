Noninterference Verification Tool (NVT)
=======================================

The NVT is a DynamoRIO client which fuzzes secret program inputs and determines
whether or not observable aspects of program execution vary with respect to
the secret inputs. The NVT returns a success (zero) result if all tests in
the target module pass. That is, the test execution traces do not vary w.r.t.
the fuzzed secret inputs. The NVT returns a failure (non-zero) result if any
test varies w.r.t. the fuzzed secret inputs.

Build and Install
-----------------

Ensure that you have installed the correct version of DynamoRIO for your system.
Details are given [here](Requirements.md).

The NVT must be enabled by setting the cmake cache option `BUILD_NVT` to `ON`.
When reconfiguring, cmake will search your system for the directory containing
`DynamoRIOConfig.cmake`. If the file cannot be found, then you will need to
manually set the `DynamoRIO_DIR` cmake variable to the directory containing
`DynamoRIOConfig.cmake`.

Once your Covert C++ build directory has been configured to build the NVT,
you can build it simply by running
```bash
$ make
```
It is highly recommended that you run your compiler over the NVT test suite to
ensure that your compiler consistently produces non-interferent binaries. To run
the tests,
```bash
$ make check-ni
```
This will use your compiler (e.g. the value in `CMAKE_CXX_COMPILER`) to compile
the tests in the Covert C++ algorithm test suite, each of which will then be run
through the NVT. By default, all compiler optimizations are turned on. You can
change or add compiler flags by setting the `NVT_TEST_CXX_FLAGS` variable in
`cmake` or `ccmake`.

Usage
-------------

The NVT may be invoked from the command line with the following command:
```bash
$ drrun -c libNVTClient.so [options ...] -- DynLoader [-d] target [args ...]
```
The available NVT options are as follows:
```
flag                 [default] Description
--------------------------------------------------------------------------------
-c                   [     0]  Cache block width (in bits)
-n                   [ 10000]  Fuzz iterations
-heap-mem            [    16]  Application heap memory (MB)
-s                   [     8]  Fuzz argument size
-l                   [    ""]  Print log info to file
-a                   [ false]  Provide additional args to Dr. Fuzz
-f                   [ false]  Expect a test to fail
-h                   [ false]  Print usage and exit
-b                   [ false]  Only analyze cache line touches
-s                   [ false]  Use the software adversary model
```
The `-n` option sets the number of fuzz iterations to run per test. `-s` sets
the size of the fuzz argument, in bytes. Use `-l` to specify a log file, where
the NVT will output the memory trace for each test and each fuzz iteration. Use
`-f` when you want the NVT to return a success (zero) result if and only if at
least one test fails. Use `-a` to provide additional arguments to the Dr. Fuzz
module. A description of the available arguments is given [here](http://drmemory.org/docs/page_drfuzz.html).
For example, you can use the mutator arguments to modify the fuzzing algorithm.
When `-d` is passed to the DynLoader, it puts DynLoader into debugging mode, in
which it prints the arguments it receives from the NVT fuzzer.

When the target application requests heap memory, those requests will be
intercepted by the NVT, which will instead provide managed memory from its
own internal heap. This ensures consistency of memory address accesses across
fuzz iterations. The amount of heap memory allowed for use by the application
can be adjusted by setting the `-heap-mem` option. The default is 16MB.

The granularity of the memory trace analysis can be adjusted by setting the
`-c` option. Using `-c <n>` masks the least significant `n` bits of each
address in the execution trace. For example, a typical x86 CPU has a cache line
size of 64 bytes, i.e. a width of log2(64) = 6 bits. If the trace analysis
should be performed at cache line granularity, the value for `-c` should be set
to 6. This value is used to determine the granularity of the analysis for
memory accesses, e.g. reads and writes. If the analysis should instead be
performed at page granularity, then on x86 the page size is 4096 bytes, and
log2(4096) = 12, so this would be the value given to `-c`.  If the `-c` option
is not given, the NVT will perform its analysis at single byte granularity
(i.e. it will use a 0-bit mask). By default, the CMake configuration will
attempt to detect your system's L1 block cache line width, and set the
`MEMORY_SIDECHANNEL_BITS` cache variable accordingly. You can also set this
value manually.

The default behavior of the NVT is to print the address, size, and r/w/bb tag
for each memory access. It may be sufficient to ignore the size of the access,
and instead analyze only which cache blocks have been touched. To enable this
behavior, use the `-b` flag.

An adversary who can view hardware-based side channels such as cache line
misses may be able to discern the order in which VSIB-addressed instructions
(e.g. AVX/AVX2 instructions like `vpgatherdd`) access memory. An adversary
who can only observe side channels through software will likely not have
this observation power. The `-s` flag performs the trace analysis with the
assumption that the adversary follows the weaker software model.

The following is a skeleton layout for an NVT test file:
```C++
#include <Covert/NVT.h>
// other #includes for the target function(s), etc.

NVT_TEST_MODULE; // exports a special symbol for use by the NVT

/**
 * Arguments for the target function(s) should be declared here. They will be
 * initialized in the NVT_TEST_INIT(*)() functions, and used in the
 * NVT_TEST_BEGIN(*)() functions.
 */

// Everything below this line is a hook function called by the DynLoader
extern "C" NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  // initialize global data structures and/or target function arguments
}
extern "C" NVT_EXPORT void NVT_TEST_BEGIN(1)() {
  // call the target function(s)
}

extern "C" NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  // initialize data for another test
}
extern "C" NVT_EXPORT void NVT_TEST_BEGIN(2)() {
  // call the target function(s) for the second test
}
```
NVT test targets must be compiled as shared objects (or DLLs on Windows). A
complete example can be found in `examples/memcmp/`. The NVT test file is
`nvt_test.cpp`. It can be built and run by making the `example-memcmp-test`
target. To see the commands that are executed, enable verbose output, e.g.
```bash
$ VERBOSE=1 make example-memcmp-test
```
This example will compile and test two different `memcmp()` implementations,
one which is optimized for performance, and one which is safe against
side-channel attacks. The former accepts only low (non-secret) inputs, while
the latter can accept any input. More details on these implementation can be
found in the [Tutorial](Tutorial.md). The high `memcmp` test should pass
and the low test should fail.

Other test examples can be found in the Noninterference test suite, in
`test/Noninterference/`.

How It Works
-------------

The NVT is a shared object, compiled as `libNVT.so` (on Linux). DynamoRIO's
`drrun` executable dynamically loads the NVT, and the NVT begins to execute
the DynLoader. When the DynLoader loads the target NVT test module, the
DynamoRIO runtime transfers control back to the NVT, which searches for the
special symbol exported by the `NVT_TEST_MODULE` definition. If this definition
is found, the NVT will search the target module for all instances of
`NVT_TEST_INIT(*)` and `NVT_TEST_BEGIN(*)` where `*` is any integer between 1 and 256.
The NVT will then inject code into all `NVT_test_init*` functions to fuzz
their `data` inputs, and pass the size of the `data` argument via the `size`
argument. The NVT will also inject code at the beginning of each
`NVT_TEST_BEGIN(*)` function to begin recording the execution memory trace.

After the target module has been transformed by the NVT, the DynLoader begins
to execute the target module. Execution proceeds roughly as follows:
```
for (i = 1; i <= 256; i++):
  if (NVT_TEST_INIT(i) exists) and (NVT_TEST_BEGIN(i) exists):
    for (j = 0; j < fuzz_iterations; j++):
      fuzz_arg <- get fuzz_arg_size bytes of fuzzed data
      NVT_TEST_INIT(i)(fuzz_arg, fuzz_arg_size);
      // begin recording execution trace
      NVT_TEST_BEGIN(i)();
      // stop recording execution trace
      if (this trace differs from previous trace):
        exit(1); // report test failure
```

For example, running the high `memcmp` example with an input size of 8 and
logging enabled for two fuzz iterations may produce the output below. The
memory trace is presented in three columns: (1) the memory address that was
accessed, (2) the size of the memory operand, and (3) the type of memory access.
The memory access type is either write (w), read (r), or execute dynamic basic
block (bb).
```
Test 1
==========

Fuzz Iteration 0:
0x7f3372309c90:  1, bb
0x7ffe4231b9d0:  8, w
0x7f337250afb8:  8, r
0x7f337250b038:  8, r
0x7f337250aff0:  8, r
0x7f337250b040:  8, r
0x7f337250afd0:  8, r
0x7f337250b860:  4, r
0x7ffe4231b9c8:  8, w
0x7f3372309920:  6, bb
0x7f337250b028:  8, r
0x7f3372309cf0:  3, bb
0x7f3372309cf5:  4, bb
0x7f3372309cfb:  2, bb
0x7f3372309e40:  3, bb
0x7f337250b060:  1, r
0x7f337250b460:  1, r
0x7f337250b461:  0, r
0x7f3372309e40:  3, bb
0x7f337250b061:  1, r
0x7f337250b461:  1, r
0x7f337250b462:  0, r
0x7f3372309e40:  3, bb
0x7f337250b062:  1, r
0x7f337250b462:  1, r
0x7f337250b463:  0, r
0x7f3372309e40:  3, bb
0x7f337250b063:  1, r
0x7f337250b463:  1, r
0x7f337250b464:  0, r
0x7f3372309e56:  1, bb
0x7ffe4231b9c8:  8, r
0x7f3372309cb3:  7, bb
0x7f337250afb0:  8, r
0x7f337250b864:  1, w
0x7ffe4231b9d0:  8, r
0x7ffe4231b9d8:  8, r
0x40080b:  5, bb
0x7ffe4231b9d8:  8, w

Fuzz Iteration 1:
0x7f3372309c90:  1, bb
0x7ffe4231b9d0:  8, w
0x7f337250afb8:  8, r
0x7f337250b038:  8, r
0x7f337250aff0:  8, r
0x7f337250b040:  8, r
0x7f337250afd0:  8, r
0x7f337250b860:  4, r
0x7ffe4231b9c8:  8, w
0x7f3372309920:  6, bb
0x7f337250b028:  8, r
0x7f3372309cf0:  3, bb
0x7f3372309cf5:  4, bb
0x7f3372309cfb:  2, bb
0x7f3372309e40:  3, bb
0x7f337250b060:  1, r
0x7f337250b460:  1, r
0x7f337250b461:  0, r
0x7f3372309e40:  3, bb
0x7f337250b061:  1, r
0x7f337250b461:  1, r
0x7f337250b462:  0, r
0x7f3372309e40:  3, bb
0x7f337250b062:  1, r
0x7f337250b462:  1, r
0x7f337250b463:  0, r
0x7f3372309e40:  3, bb
0x7f337250b063:  1, r
0x7f337250b463:  1, r
0x7f337250b464:  0, r
0x7f3372309e56:  1, bb
0x7ffe4231b9c8:  8, r
0x7f3372309cb3:  7, bb
0x7f337250afb0:  8, r
0x7f337250b864:  1, w
0x7ffe4231b9d0:  8, r
0x7ffe4231b9d8:  8, r
0x40080b:  5, bb
0x7ffe4231b9d8:  8, w
```

Debugging the NVT
-----------------

The NVT will emit logging/debugging information if `drrun` is invoked as
follows:
```bash
$ drrun -debug -loglevel 4 -logmask 0xFF000000 -logdir <where-to-emit-logs> \
    -c libNVTClient.so <NVT-options> -- DynLoader <target-application>
```
The flags are documented here:
- `-debug`: <http://dynamorio.org/docs/using.html>
- `-loglevel`: <http://dynamorio.org/docs/using.html#op_loglevel>
- `-logmask`: <http://dynamorio.org/docs/using.html#op_logmask>
- `-logdir`: <http://dynamorio.org/docs/using.html#op_logdir>

Note that logging is only enabled for `DEBUG` builds of the NVT (i.e. `NDEBUG`
is not defined).
