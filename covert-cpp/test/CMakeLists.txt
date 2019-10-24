if (CMAKE_CFG_INTDIR STREQUAL ".")
  set(COVERT_BUILD_MODE ".")
else ()
  set(COVERT_BUILD_MODE "%(build_mode)s")
endif ()
string(REPLACE ${CMAKE_CFG_INTDIR} ${COVERT_BUILD_MODE} COVERT_TOOLS_BINARY_DIR ${COVERT_RUNTIME_OUTPUT_INTDIR})
string(REPLACE ${CMAKE_CFG_INTDIR} ${COVERT_BUILD_MODE} COVERT_LIBRARY_DIR ${COVERT_LIBRARY_OUTPUT_INTDIR})

set (TEST_CPLUSPLUS_STD "c++${COVERT_CXX_STANDARD}")
set (TESTSUITE_MODULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/modules)

find_program (LLVM_EXTERNAL_LIT NAMES llvm-lit lit-script.py lit.py lit)
if ("${LLVM_EXTERNAL_LIT}" STREQUAL "LLVM_EXTERNAL_LIT-NOTFOUND")
  message (FATAL_ERROR "Could not find the lit executable!")
endif ()
if ((NOT DEFINED _LLVM_EXTERNAL_LIT) OR (NOT ${_LLVM_EXTERNAL_LIT} STREQUAL ${LLVM_EXTERNAL_LIT}))
  execute_process (COMMAND ${LLVM_EXTERNAL_LIT} --version
    RESULT_VARIABLE LIT_COMMAND_RESULT
    OUTPUT_VARIABLE LIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if (NOT ${LIT_COMMAND_RESULT})
    message (STATUS "Found ${LIT_VERSION}: ${LLVM_EXTERNAL_LIT}")
  else ()
    message (FATAL_ERROR "lit command does not work: ${LLVM_EXTERNAL_LIT}")
  endif ()
  set (_LLVM_EXTERNAL_LIT ${LLVM_EXTERNAL_LIT} CACHE INTERNAL "" FORCE)
endif ()
set (LIT_COMMAND ${LLVM_EXTERNAL_LIT})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  find_program (FILECHECK FileCheck)
  if (FILECHECK STREQUAL "FILECHECK-NOTFOUND")
    set (FILECHECK_DEPS FileCheck)
  endif ()
  find_program (NOT_PROG not)
  if (NOT_PROG STREQUAL "NOT_PROG-NOTFOUND")
    set (NOT_PROG_DEPS not)
  endif ()
endif ()

if (WIN32)
  find_program (WIN_DIFF diff)
  if (WIN_DIFF STREQUAL "WIN_DIFF-NOTFOUND")
    message (FATAL_ERROR "Could not find 'diff'. This likely means that you did not install \
                          GnuWin32, or did not include it in your system path.")
  endif (WIN_DIFF STREQUAL "WIN_DIFF-NOTFOUND")
endif (WIN32)

# Visual Studio can't add lit targets as dependencies to 'check', because the lit targets
# use EXCLUDE_FROM_DEFAULT_BUILD
if (NOT MSVC)
  add_custom_target (check)
endif ()

# For some reason, Xcode treats test pass outputs as errors, so we suppress those outputs
if (XCODE)
  set (TOOLS_TEST_EXTRA_ARGS ${TOOLS_TEST_EXTRA_ARGS} -q)
endif ()

add_subdirectory (Tools)
option (ENABLE_DEV_TESTS "Enable Covert C++ development tests")
if (ENABLE_DEV_TESTS)
  add_subdirectory (Covert)
endif ()
if (BUILD_NVT)
  add_subdirectory (Noninterference)
endif ()
