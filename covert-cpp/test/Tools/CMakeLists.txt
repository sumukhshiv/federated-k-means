if (NOT CMAKE_CFG_INTDIR STREQUAL ".")
  file (GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/lit.gen.cfg
    INPUT ${CMAKE_CURRENT_SOURCE_DIR}/lit.gen.cfg.in
  )
else ()
  file (GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lit.gen.cfg
    INPUT ${CMAKE_CURRENT_SOURCE_DIR}/lit.gen.cfg.in
  )
endif ()

if (APPLE)
  get_filename_component (CMAKE_CXX_COMPILER_DIR ${CMAKE_CXX_COMPILER} DIRECTORY)
  set (CMDLINE_TOOLS_DIR "/Library/Developer/CommandLineTools/usr/")
  set (XCODE_TOOLS_DIR "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/")
  find_path (LIBCXX_INCLUDES_DIR
    NAMES __libcpp_version
    HINTS
      /usr/include/c++/v1
      ${CMDLINE_TOOLS_DIR}/include/c++/v1
      ${XCODE_TOOLS_DIR}/include/c++/v1
      ${CMAKE_CXX_COMPILER_DIR}/../include/c++/v1
      ${LLVM_DIR}/../../../include/c++/v1
    DOC "Path to libc++ header files"
  )
  if ("${LIBCXX_INCLUDES_DIR}" STREQUAL "LIBCXX_INCLUDES_DIR-NOTFOUND")
    message (FATAL_ERROR "Could not find libc++ headers! Please Specify in LIBCXX_INCLUDES_DIR")
  else ()
    if ((NOT DEFINED _LIBCXX_INCLUDES_DIR) OR (NOT ${_LIBCXX_INCLUDES_DIR} STREQUAL ${_LIBCXX_INCLUDES_DIR}))
      if (EXISTS ${LIBCXX_INCLUDES_DIR}/__libcpp_version)
        file (STRINGS ${LIBCXX_INCLUDES_DIR}/__libcpp_version LIBCXX_VERSION REGEX "[0-9]")
        message (STATUS "Found libc++ headers (v${LIBCXX_VERSION}): ${LIBCXX_INCLUDES_DIR}")
        set (_LIBCXX_INCLUDES_DIR ${LIBCXX_INCLUDES_DIR} CACHE INTERNAL "" FORCE)
      else ()
        message (FATAL_ERROR "LIBCXX_INCLUDES_DIR invalid")
      endif ()
    endif ()
  endif ()
endif ()

configure_file (check_refactor_tool.py.in check_refactor_tool.py)
set (CHECK_REFACTOR_TOOL "${CMAKE_CURRENT_BINARY_DIR}/check_refactor_tool.py")

set(TOOLS_TEST_DEPS
  c2cpp
  cpp2covert
  ${FILECHECK_DEPS}
)

add_lit_target (check-tools "Running the Covert C++ Tools regression tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${TOOLS_TEST_DEPS}
  ARGS ${TOOLS_TEST_EXTRA_ARGS}
)
if (TARGET check)
  add_dependencies(check check-tools)
endif ()
set_target_properties(check-tools PROPERTIES FOLDER "Tests")

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
)

function (configure_exec_test target)
  add_dependencies (check-tools ${target})
  get_target_property (SOURCE_FILES ${target} SOURCES)
  list (GET SOURCE_FILES 0 MAIN_SOURCE_FILE)
  get_filename_component (MAIN_SOURCE_FILE_NAME ${MAIN_SOURCE_FILE} NAME)
  set_target_properties (${target} PROPERTIES
    PREFIX ""
    SUFFIX ".out"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    RUNTIME_OUTPUT_NAME ${MAIN_SOURCE_FILE_NAME}
    EXCLUDE_FROM_ALL TRUE
    FOLDER "Tests/Tools Tests"
    VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
  )
endfunction (configure_exec_test)

add_subdirectory (Oblivious)
