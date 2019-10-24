Covert C++
===============

Covert C++ is a metaprogramming technique which detects and prevents
side-channel vulnerabilities. In brief, it provides containers for
primitive data (e.g. int, char *, etc.) which assign security labels to data.
A security label can either be high (H) to denote secret data, or low (L) to
mark data that does not require confidentiality. Covert C++ uses C++'s
Turing-complete template type system to ensure that H data cannot be used in
such a manner that would expose a side-channel vulnerability. Any potential
vulnerability will be signaled to the user as a compiler error.

Documentation Index
-------------------

1. [Package Contents](docs/Contents.md)
2. [Requirements](docs/Requirements.md)
3. [Build and Install](docs/Install.md)
4. [Tutorial](docs/Tutorial.md)
5. [Language Reference](docs/LanguageReference.md)
6. [Noninterference Verification Tool](docs/NVT.md)
7. [Refactoring Tools](docs/Refactoring.md)
8. [Development](docs/Development.md)
9. [Future Projects](docs/FutureProjects.md)

Quick Start
-------------------

If you have a C++17-compatible compiler, you can use Covert C++ right out of
the box. Just run
```bash
$ cd <path-to-covert-cpp>
$ mkdir build
$ cd build
$ cmake -G "<your-build-env>" -DBUILD_COVERT_TOOLCHAIN=OFF \
    -DCMAKE_INSTALL_PREFIX=<prefix> ..
$ cmake --build . --target install
```
To find the correct generator string for the `-G` flag for your build
environment, see the list of supported CMake generators [here](https://cmake.org/cmake/help/v3.8/manual/cmake-generators.7.html).
If your compiler does not fully support C++17, then the
`CXX_SUPPORTS_COVERT_CXX` test may fail in the fourth command. Covert C++
is extremely demanding on the compiler. As a result, few compilers are able
to compile Covert C++ code at this time. The clang >=5.0 compiler is the best
option at the time of this writing. The fifth command above will install the
Covert C++ header files in the directory specified in `<prefix>`. If `<prefix>`
requires root permissions for writing, then you should invoke this command with
`sudo` (UNIX-like platforms only).

**NOTE:** The following compilers have been used to successfully compile this
version of Covert C++:
- `clang` (>= 5.0)
- `gcc-8`
- `cl` (Visual Studio 2017 >=15.8)

**NOTE:** Advanced Vector Extensions 2 (AVX2) are required to run the Covert
C++ oblivious algorithms. AVX2 instructions are supported on Intel Haswell or
newer, or AMD Excavator or newer.

Before diving in, you should at least familiarize yourself with the
[tutorial](docs/Tutorial.md). To build the accompanying Covert C++ toolchain,
please refer to the [build instructions](docs/Install.md). After installing
Covert C++ on your system, you can import it into an existing CMake project
by adding the line
```
find_package (covert-cpp CONFIG)
```
to your `CMakeLists.txt`.
