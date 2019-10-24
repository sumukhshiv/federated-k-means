Build and Installation
=======================

Before proceeding, make sure that you have installed all of the necessary
[requirements](docs/Requirements.md) for your platform. Then [clone](README.md)
the Covert C++ repository.

The Covert C++ toolchain uses the cmake build system for cross-platform builds.
The following is a list of Covert C++ cmake configuration options, which can
be configured using the cmake GUI interface (Windows) or the ncurses-based
ccmake program (UNIX-like systems).

- `ENABLE_DOXYGEN`: Enable the `doxygen` target, which builds doxygen
  documentation for the refactoring tools and related libraries.
- `BUILD_COVERT_TOOLCHAIN` (default: `ON`): Add the Covert C++ toolchain to
  the `all` target, except for the NVT which must be enabled separately by the
  `BUILD_NVT` option. Set `BUILD_COVERT_TOOLCHAIN` to `OFF` if you just want
  to install the Covert C++ header files and/or build the examples.
- `BUILD_NVT`: Enable the `NVT` and `DynLoader` targets, as well as the
  `check-ni` target for the noninterference test suite. The NVT is described
  in further detail [here](NVT.md).
- `ENABLE_DEV_TESTS`: Enable the `check-dev` target for the Covert C++
  development test suite, described in further detail [here](Development.md).
- `LLVM_EXTERNAL_LIT`: Location of the `lit` executable, required for running any of
  the test suites.
- `WIN_DIFF`: (Windows only) Location of the `diff.exe` program, which is part
  of the GnuWin32 package. Required for the test suites.
- `COVERT_CXX_STANDARD`: The C++ standard to use when building the examples
  and the test suites. Currently options `14` and `17` are supported by Covert
  C++.

Other cmake cache variables may appear when any of the above options are
enabled. These other options are either explained with a comment in cmake, or
in their respective chapter of the documentation.

Other common cmake configuration options are described [here](https://cmake.org/Wiki/CMake_Useful_Variables).

Unix-like Systems
-----------------------

Navigate to the directory where you downloaded or installed Covert C++. Then
execute the following:
```bash
$ cd covert-cpp
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="<LLVM install path>\lib\cmake\llvm" ..
$ make
```
If `cmake` or `make` fails, then you are most likely missing a requirement.
Please consult with the [Requirements](docs/Requirements.md) document for more
information. Otherwise, run the test suite to ensure that your setup is ready
to run Covert C++ code:
```bash
$ make check
```
If any of the tests fails, then please run the command
```bash
$ lit -a test/
```
and send the output to Scott Constable at <sdconsta@syr.edu>.
If you can run `make check` with all tests passing, you may proceed to
install the toolchain:
```bash
$ sudo make install
```
This will install the Covert C++ headers, and the Covert C++ refactoring tools.

Additionally, most of this repository has been documented with Doxygen. To
build the Doxygen HTML documentation, build the `doxygen` target, e.g.
```bash
$ make doxygen
```

MacOS (Xcode)
-----------------------

Navigate to the directory where you downloaded or installed Covert C++. Then
execute the following:
```bash
$ cd covert-cpp
$ mkdir build
$ cd build
$ cmake -G "Xcode" -DLLVM_DIR="<LLVM install path>\lib\cmake\llvm" ..
```
If `cmake` succeeds, it has created a `covert-cpp.xcodeproj` file in your
`build\` directory, which you can open in Xcode. You may build the "ALL_BUILD"
target. If that succeeded, then build the "check" target to make sure everything
is OK. If all tests pass, you may build the "install" target, which will install
the Covert C++ toolchain to the directory specified in `CMAKE_INSTALL_PREFIX`.

Windows (Visual Studio)
-----------------------

Navigate to the directory where you downloaded or installed Covert C++. Then
execute the following:
```bash
$ cd covert-cpp
$ mkdir build
$ cd build
$ cmake -G "Visual Studio <version> <arch>" ^
    -DLLVM_DIR="<LLVM install path>\lib\cmake\llvm" ..
```
If `cmake` succeeds, it has created a `covert-cpp.sln` file in your `build\`
directory, which you can open in Visual Studio. Make sure that your
configuration and target architecture match those of your LLVM installation.
For instance, if you built LLVM "Release" for "x64", then you should use these
same configuration options for the Covert C++ toolchain. Now build the "ALL_BUILD"
target. If that succeeded, then build the "check" target to make sure everything
is OK. If all tests pass, you may build the "INSTALL" target, which will install
the Covert C++ toolchain to the directory specified in `CMAKE_INSTALL_PREFIX`.

Building the Documentation
--------------------------

Covert C++ and the Covert C++ toolchain have been scrupulously documented in
JavaDox-style and markdown-style comments which can be processed by the
[Doxygen](http://www.stack.nl/~dimitri/doxygen/) tool. To build the Doxygen
HTML documentation, set `ENABLE_DOXYGEN` to `ON`, then build the `doxygen` target.
This will populate `build/docs/doxygen/html` with the HTML documentation. To view
the documentation, open `index.html` in your web browser.
