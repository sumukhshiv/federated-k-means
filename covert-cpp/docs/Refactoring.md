Refactoring Tools
=======================

The Covert C++ toolchain currently has two refactoring tools:

- `c2cpp`: Performs interactive, semi-automatic refactoring to transform
  C-compliant source code into C++-compliant source code. Contrary to popular
  belief, C++ is backwards-incompatible with C in many ways. A brief summary
  of these issues is given [here](https://en.wikipedia.org/wiki/Compatibility_of_C_and_C%2B%2B).
- `cpp2covert`: Performs interactive, semi-automatic refactoring to transform
  C++ code into Covert C++ code. That is, it transforms primitive data types
  (e.g. `int`) into Covert C++ SE types (e.g. `SE<int, L>`).

There is also a Python-based tool, `run-refactor`, which performs whole-project
refactoring. Further descriptions of each tool are given in their respective
sections below.

The refactoring tools are based loosely on `clang-tidy`, and work in similar
fashion. For example, the most basic usage of `cpp2covert` looks something like
this:
```bash
$ cpp2covert -checks=* my_source.cpp --
```
The `--` at the end of the command tells the refactoring tool not to use a
compile command database to parse the source file. In general, the use of a
compile command database is highly recommended, as this will ensure the most
accurate parsing, and thus the most accurate refactoring results. If your
project has a compile command database, you may specify the path to that
database with `-p`, e.g.
```bash
$ cpp2covert -p my_build_dir/ -checks=* my_source.cpp
```
where `my_build_dir` contains the project's `compile_commands.json` file.

By default, these tools will not transform any code. Instead they will emit
diagnostics to the terminal with refactoring recommendations. Due to the
complexity of the C and C++ languages, fully automatic refactoring is not
possible (e.g. because of the preprocessor). When a tool is confident that it
can refactor a segment of code without causing any issues, it will emit a
fix-it hint. Otherwise, it will usually give a recommendation as to
how to manually refactor a segment of code. For instance, a tool will
not be able to automatically refactor code defined inside a macro because
refactoring recommendations are contextual, and the meaning of a macro
will differ depending on the context in which it is expanded. For example,
```
DeclTest.cpp:13:8: warning: 'item' declared with primitive type 'char [ITEM_SIZE]'
  char item[ITEM_SIZE];
  ~~~~ ^
  SE<char, L>
DeclTest.cpp:29:3: warning: '_i' declared with primitive type 'int'
    MACRO2;
    ^
DeclTest.cpp:8:20: note: expanded from macro 'MACRO2'
  #define MACRO2 int _i;
                     ^
DeclTest.cpp:8:20: note: use type 'SE<int, L>' instead
  #define MACRO2 int _i;
                     ^
```
The first warning can be fixed automatically by `cpp2covert`, which it indicates
with the fix-it hint underneath the warning. The second warning cannot be
trivially fixed because it results from a macro expansion. So `cpp2covert`
identifies the source location of the problem, and suggests the appropriate
`SE` type to use instead. `cpp2covert` will apply the fix-its to the source code
automatically when the `-fix` option is used.

Note that, by default, the refactoring tools will not refactor code in system
libraries (e.g. libc++). To override this behavior, use the `-system-headers`
option.

`c2cpp`
----------------

```
USAGE: c2cpp [options] <source0> [... <sourceN>]

OPTIONS:

Generic Options:

  -help                      - Display available options (-help-hidden for more)
  -help-list                 - Display list of available options (-help-list-hidden for more)
  -version                   - Display the version of this program

c2cpp common options:

  -export-fixes=<filename>   - YAML file to store suggested fixes in. The stored
                               fixes can be applied to the input source code with
                               clang-apply-replacements
  -extra-arg=<string>        - Additional argument to append to the compiler command line
  -extra-arg-before=<string> - Additional argument to prepend to the compiler command line
  -fix                       - Apply suggested fixes, if possible
  -header-filter=<string>    - Regular expression matching the names of the
                               headers to output diagnostics from. Diagnostics
                               from the main file of each translation unit are
                               always displayed.
  -p=<string>                - Build path
  -system-headers            - Display the errors from system headers.

-p <build-path> is used to read a compile command database.

        For example, it can be a CMake build directory in which a file named
        compile_commands.json exists (use -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
        CMake option to get this output). When no build path is specified,
        a search for compile_commands.json will be attempted through all
        parent paths of the first input file . See:
        http://clang.llvm.org/docs/HowToSetupToolingForLLVM.html for an
        example of setting up Clang Tooling on a source tree.

<source0> ... specify the paths of source files. These paths are
        looked up in the compile command database. If the path of a file is
        absolute, it needs to point into CMake's source tree. If the path is
        relative, the current working directory needs to be in the CMake
        source tree and the file must be in a subdirectory of the current
        working directory. "./" prefixes in the relative files will be
        automatically removed, but the rest of a relative path must be a
        suffix of a path in the compile command database.
```

`cpp2covert`
----------------

```
USAGE: cpp2covert [options] <source0> [... <sourceN>]

OPTIONS:

Generic Options:

  -help                      - Display available options (-help-hidden for more)
  -help-list                 - Display list of available options (-help-list-hidden for more)
  -version                   - Display the version of this program

cpp2covert common options:

  -checks=<string>           - Comma-separated list of checks to apply. Use
                               "-checks=*" to enable all checks.
  -export-fixes=<filename>   - YAML file to store suggested fixes in. The stored
                               fixes can be applied to the input source code with
                               clang-apply-replacements
  -extra-arg=<string>        - Additional argument to append to the compiler command line
  -extra-arg-before=<string> - Additional argument to prepend to the compiler command line
  -fix                       - Apply suggested fixes, if possible
  -header-filter=<string>    - Regular expression matching the names of the
                               headers to output diagnostics from. Diagnostics
                               from the main file of each translation unit are
                               always displayed.
  -linked-with-covert        - Enable when the target source file(s) has been linked with the CMake
                               'Covert' library. E.g. target_link_libraries(<target> Covert)
  -list-checks               - List all supported checks and exit.
  -p=<string>                - Build path
  -secret-only               - Only refactor declarations marked 'SECRET'
  -system-headers            - Display the errors from system headers.

-p <build-path> is used to read a compile command database.

  For example, it can be a CMake build directory in which a file named
  compile_commands.json exists (use -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  CMake option to get this output). When no build path is specified,
  a search for compile_commands.json will be attempted through all
  parent paths of the first input file . See:
  http://clang.llvm.org/docs/HowToSetupToolingForLLVM.html for an
  example of setting up Clang Tooling on a source tree.

<source0> ... specify the paths of source files. These paths are
  looked up in the compile command database. If the path of a file is
  absolute, it needs to point into CMake's source tree. If the path is
  relative, the current working directory needs to be in the CMake
  source tree and the file must be in a subdirectory of the current
  working directory. "./" prefixes in the relative files will be
  automatically removed, but the rest of a relative path must be a
  suffix of a path in the compile command database.
```

The `cpp2covert` tool is internally complex, executing different checks at
different stages of source code processing. For instance, the casting check is
done while the AST is built, and the `SE` type check is done after the AST has
been built. For best results, we recommend applying the tool four times:
1. Fix any identifiers which conflict with Covert C++ keywords:
```bash
cpp2covert -p <build-dir> -fix -checks=keywords <source0> [... <sourceN>]
```
2. Include the Covert C++ headers, if you haven't already. The "types" check
   will always begin by looking for these headers. If it doesn't find them,
   it will include them automatically.
```bash
cpp2covert -p <build-dir> -fix -checks=types <source0> [... <sourceN>]
```
3. Refactor the types, as necessary:
```bash
cpp2covert -p <build-dir> -fix -checks=types <source0> [... <sourceN>]
```
3. Refactor any other issues (e.g. explicit casting), as necessary:
```bash
cpp2covert -p <build-dir> -fix -checks=* <source0> [... <sourceN>]
```

`cpp2covert` currently supports three checks:
- `keywords`: Finds identifiers such as `SE` or `L` which are also Covert C++
  keywords, and can optionally refactor them which a leading underscore.
- `types`: Replaces primitive types with their analogous `SE` form.
- `casting`: After refactoring primitive types to Covert C++ types, the named
  casts (e.g. `static_cast`, `reinterpret_cast`, etc.) that are now being
  applied to `SE` types may need to be converted to their `se_*` form. This
  check assists with that conversion.

Additionally, `cpp2covert` supports a `SECRET` declaration annotation. When a
declaration is marked `SECRET` (and has a primitive type), that declaration is
refactored with a `H` security label instead of `L`. If the type is a pointer,
pointer-to-pointer, etc., then the last label (referring to the deepest
pointee) is refactored to `H`, while all preceding labels are set to `L`. For
instance,
```C++
SECRET int *p;
```
will refactor to
```C++
SECRET SE<int *, L, H> p;
```
That is, a low pointer to a high `int`.

`run-refactor`
----------------

```
usage: run-refactor.py [-h] [-tool PATH]
                       [-clang-apply-replacements-binary PATH]
                       [-header-filter HEADER_FILTER] [-j JOBS] [-fix]
                       [-format] [-p BUILD_PATH] [-sources FILE [FILE ...]]
                       [-arg ARG]

Runs TOOL over all files in a compilation database. Requires TOOL and clang-
apply-replacements in $PATH.

optional arguments:
  -h, --help            show this help message and exit
  -tool TOOL            The refactoring tool to run
  -clang-apply-replacements-binary PATH
                        path to clang-apply-replacements binary
  -header-filter HEADER_FILTER
                        regular expression matching the names of the headers
                        to output diagnostics from. Diagnostics from the main
                        file of each translation unit are always displayed.
  -j JOBS               number of TOOL instances to be run in parallel.
  -fix                  apply fix-its
  -format               Reformat code after applying fixes
  -p BUILD_PATH         Path used to read a compile command database.
  -sources FILE [FILE ...]
                        source files to be processed (regex on path)
  -arg ARG              Pass additional arguments to TOOL
```

If your project uses a compile command database, then `run-refactor` can allow
you to easily execute the Covert C++ refactoring tools over all or some of your
project. For example,
```bash
$ run-refactor.py -tool cpp2covert -p my_build_dir/ -arg=-checks=* \
    -sources src1.cpp src2.cpp -j 2 -fix
```
will run `cpp2covert` with all checks enabled over `src1.cpp` and `src2.cpp`,
in parallel. If no source files are specified, then all source files in the
compile commands database are processed. The `-sources` option can also handle
filename regular expressions. The `-fix` option passes `-fix` to each instance
of `TOOL` (see above).

**NOTE:** The target project must be configured to use the C++17 standard.
It may also be necessary to configure the project to use libc++.
