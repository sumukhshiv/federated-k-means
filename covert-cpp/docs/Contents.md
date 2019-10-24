Package Contents
================

- `cmake/`: Helper CMake modules
- `docs/`: Configuration files for doxygen, and Markdown web documentation
- `examples/`: Example programs written in Covert C++
- `include/`:
    - `Covert/`: Covert C++ header files
    - `NVT/`: Noninterference Verification Tool (NVT) interface header files
    - `Oblivious/`: Header (interface) files for the Oblivious memory library
- `lib/`:
    - `Oblivious/`: Shared library which exports APIs to facilitate oblivious
      computations.
- `test/`: Covert C++ tests using LLVM lit
    - `Covert/`: Covert C++ development test suite
    - `Noninterference/`: Covert C++ noninterference test suite
    - `Tools/`: Covert C++ refactoring tools test suite
- `tools/`: Executables and scripts for the Covert C++ toolchain
    - `nvt/`: Noninterference Verification Tool (NVT)
    - `c2cpp/`: Helper tool to convert C files into C++ files
    - `cpp2covert/`: Refactor C++ source files into Covert C++
    - `include/`:
      - `Diagnostic/`: Supplementary clang DiagnosticConsumer headers
    - `lib/`:
        - `Diagnostic/`: Supplementary clang DiagnosticConsumers
    - `run-refactor.py`: Runs refactoring tool(s) in parallel
    - `utils/`: Helper utilities to support the test framework
