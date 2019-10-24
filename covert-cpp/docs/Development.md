Covert C++ Development Guide
============================

This document sets some guidelines for developing and maintaining
the various components of the Covert C++ toolchain. Each section
below is dedicated to a particular component.

Covert C++
-----------------------

If you want to edit the Covert C++ header files, e.g. `Covert/Covert.h`,
you must consult with the development test suite, located in
`test/Covert/`. These are regression tests which rigorously cover
every aspect of the Covert C++ extensions; any failure may indicate that
a change has broken something.

To maintain consistency across platforms, the dev tests require clang,
libc++, and the LLVM IR interpreter (`lli`). Presently, the libc++ ABI
is not supported on Windows, so the dev tests cannot be run on Windows.
On MacOS, if you installed the LLVM requirements using homebrew, then you
should already have the correct versions of clang, libc++, and lli. On
Ubuntu/Debian systems, libc++ can be installed by running the following command:
```bash
$ sudo apt install libc++1 libc++-dev
```
Note that if your libc++ version is less than 3.9.1, you may not be able to run
the development tests in C++17 mode.

If all the requirements have been satisfied, then you can set `ENABLE_DEV_TESTS`
to `ON` in your Covert C++ cmake configuration, which will enable the development
tests. Then try to run
```bash
$ make check-dev
```
All tests should pass.

**Note:** You may have to point `cmake` to your libc++ installation by setting
the `DEV_LIBCXX` and `DEV_LIBCXX_INCLUDES_DIR` variables.

Refactoring Tools
-----------------------

The Covert C++ refactoring tools' source can be found in the `tools/` directory,
and the test suite exists in `test/Tools/`, and can be run by
```bash
$ make check-tools
```
The refactoring tools are designed to work in a manner similar to clang-tidy.
Each tool should exist in its own subdirectory of `tools/`, its tests shall
exist in their own subdirectory of `test/Tools/`, and it shall be compatible
with the whole-program refactoring tool `run-refactor.py`.ls

Additional Guidelines
-----------------------

All compiled C and C++ source files should be checked for conformance by
clang-tidy before each pull request. To use clang-tidy, you must first create a
JSON compilation database for the Covert C++ toolchain. CMake will do this for
you if you enable the `CMAKE_EXPORT_COMPILE_COMMANDS` option. The next time you
run `make`, cmake will then create a `compile_commands.json` file in your
project build directory. You should then be able to run clang-tidy from the
top-level Covert C++ directory with the following command:
```bash
$ clang-tidy -p <build-directory>
```
where `<build-directory` contains `compile_commands.json`. If clang-tidy
reports any warnings or errors in user code, please fix these before making a
pull request.

Additionally, all *.c, *.cpp, and *.h files in the `tools/` and `include/`
directories should be formatted by clang-format (please do not format the files
in the `test/` directory). Instructions on how to use clang-format can be found
[here](https://clang.llvm.org/docs/ClangFormat.html). The easiest way to use it
is to integrate clang-format into your IDE or text editor. Please use the
`.clang-format` configuration in the top-level Covert C++ directory with
`clang-format`.
