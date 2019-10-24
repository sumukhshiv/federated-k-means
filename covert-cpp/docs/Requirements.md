Requirements
=======================

Summary of Requirements
-----------------------

The Covert C++ header files found in `include/Covert` can be included in any
existing C++ project. The only requirement is that the code must be compiled
with a C++17-compatible compiler, using the, e.g.
by using the `-std=c++17` flag with `g++`.

Below are the additional requirements for building and testing the Covert C++
toolchain:

| Package                  | Version       | Required For                      |
| :----------------------- |:-------------:| ---------------------------------:|
| CMake                    | >=3.8.2       | Build System                      |
| GNU Make                 | 3.79, 3.79.1  | Build System (Linux/MacOS only)   |
| Visual Studio            | >=2013        | Build System (Windows only)       |
| Doxygen                  | >=1.8.0       | HTML Documentation                |
| Python                   | 2.7           | Test Suite                        |
| Lit                      | >=0.5.0       | Test Suite                        |
| GnuWin32 Tools           | >=0.6.3       | Test Suite (Windows only)         |
| LLVM-runtime/Clang       | >=5.0         | C/C++ Compiler, Test Suite        |
| zlib                     | >=1.2.3.4     | LLVM                              |
| LLVM                     | >=5.0         | Refactoring Tools                 |
| libclang                 | >=5.0         | Refactoring Tools                 |
| DynamoRIO                | 7.0.0-RC1     | NVT                               |

**Note:** There are currently some issues with Covert C++ and LLVM >= 7.0.0. It
is currently better to use LLVM 5 or 6.

Note that package versions other than those listed above may also work, but
are not supported.

Below we provide instructions for installing the Covert C++ toolchain
requirements on a variety of platforms. The Covert C++ toolchain may also be
built on other platforms, but it has only been tested on the platforms
described below.

Obtaining DynamoRIO
-----------------------

The Noninterference Verification Tool (NVT) requires that DynamoRIO be installed
on your system. Note that at the time of this writing, Linux and Windows are the only
supported platforms for DynamoRIO (support for macOS is anticipated in the near
future). The binaries for DynamoRIO can be obtained [here](https://github.com/DynamoRIO/dynamorio/wiki/Downloads).

Note that the NVT is not required to use Covert C++, though it is recommended to
use the NVT to test secure functions.

**Note:** If you're using a newer version of CMake, then CMake may issue
compatibility warnings about DynamoRIO and/or Dr. Memory. This should not cause
any problems. The warnings can be suppressed by adding `-Wno-deprecated` to the
CMake command line:
```bash
$ cd build
$ cmake -Wno-deprecated ..
```

Ubuntu/Debian
-----------------------

**Note:** Tested on Ubuntu 16.04 LTS Desktop (x86-64)

First install all of the required `apt` packages:
```bash
$ sudo apt update
$ sudo apt install git cmake python python-pip clang-5.0 zlib1g-dev \
    llvm-5.0-dev libclang-5.0-dev
```
If your package manager cannot find the 5.0 distribution of LLVM, then it may
not be officially supported for your version of Ubuntu/Debian. If this is the case,
follow the directions [here](http://apt.llvm.org/) to add the llvm-toolchain repositories
for your version of Ubuntu/Debian (you may also have to add the LLVM repo public
key to your system's keychain).

Covert C++ uses the LLVM Integrated Tester (lit) to run its test suites. We
can install it as a Python package:
```bash
$ pip install --user lit
$ which lit
```
If the `which lit` command returns nothing, then the directory containing your
local Python package binaries is not in your `$PATH`. Ensure that this is the
case before attempting to run the Covert C++ test suite.

macOS
-----------------------

**Note:** Tested on 10.13 High Sierra

Ensure that you have installed Xcode and the Xcode command-line tools.
Directions on how to do this can be found elsewhere. The easiest way to install
the remaining requirements is to use [Homebrew](https://brew.sh). The following
commands should install all of the necessary requirements:
```bash
$ brew update
$ brew install cmake python llvm
```
Covert C++ uses the LLVM Integrated Tester (lit) to run its test suites. We
can install it as a Python package:
```bash
$ pip install --user lit
$ which lit
```
If the `which lit` command returns nothing, then the directory containing your
local Python package binaries is not in your `$PATH`. Ensure that this is the
case before attempting to run the test suite.

Windows (Visual Studio)
-----------------------

**IMPORTANT** Windows is the trickiest target for the LLVM toolchain. please
read all of the directions before proceeding to install LLVM/Clang on your
system.

On Windows you will need to build the entire LLVM/Clang platform from sources,
because the prepackaged LLVM/Clang binaries for Windows do not include the
development libraries.

We recommend using Visual Studio to install git. The other requirements can
be acquired as follows:
- Python2: https://www.python.org/downloads/windows/
- CMake: https://cmake.org/download/
- GnuWin32: http://gnuwin32.sourceforge.net (Follow the install directions
  very carefully!)

You may need to add these programs to your system's PATH environment variable.
This includes the `Scripts\` subdirectory of your Python2 installation, which
contains `pip.exe`. You can use `pip` to install `lit`:
```bash
$ pip install lit
$ which lit
```
If `which lit` cannot find `lit`, then your python packages subdirectory is
not in your PATH.

Now open a command prompt, and navigate to the directory where you would like
to build and install LLVM/Clang. You may then enter the following sequence
of commands:
```bash
$ git clone https://github.com/llvm-mirror/llvm.git
$ cd llvm
$ git checkout release_60
$ cd tools
$ git clone https://github.com/llvm-mirror/clang.git
$ cd clang
$ git checkout release_60
$ cd ../..
$ mkdir build
$ cd build
$ cmake -Thost=<arch> -G "Visual Studio <version> <os>" -DLLVM_INSTALL_UTILS=ON ^
  -DCMAKE_INSTALL_PREFIX=install/ -DLLVM_ENABLE_DIA_SDK=OFF ..
```
**IMPORTANT:** Before building LLVM/Clang, please review the suggestions below:
- By default, the Visual Studio project files generated by CMake use the
  32-bit toolset. If you are developing on a 64-bit version of Windows, then
  use `-Thost=x64` and `-G "Visual Studio <version> Win64"`.
- You can identify the correct Visual Studio version argument for CMake
  [here](https://cmake.org/cmake/help/v3.9/manual/cmake-generators.7.html#visual-studio-generators).
  For example, if you're using Visual Studio 2017 with 64-bit Windows, then
  you would invoke CMake like this:
```bash
$ cmake -Thost=x64 -G "Visual Studio 15 Win64" ...
```
- By default, Visual Studio will build LLVM for debugging, which
  will consume a very large (>10GB) amount of disk space. If you will not need
  to debug LLVM/Clang, then you should select the "Release" configuration in
  Visual Studio before building LLVM/Clang.
- If you are working on a 64-bit flavor of Windows, make sure that the target
  architecture in Visual Studio is set to "x64".
- The command example above installs LLVM/Clang in a sub-directory of the
  `build\` directory that you created. If you plan to use LLVM/Clang in other
  projects, you may want to install LLVM/Clang in a more accessible location,
  e.g. `C:\Program Files\LLVM`. Note that if you select a system-wide location
  as your `CMAKE_INSTALL_PREFIX`, you may need to run Visual Studio with
  administrator privileges in order to build the INSTALL target.

If the `cmake` command succeeded, then it should have created an `LLVM.sln`
solution file in the `build\` directory. Open this file in the corresponding
version of Visual Studio, then build the "INSTALL" target. This may take a
while!
