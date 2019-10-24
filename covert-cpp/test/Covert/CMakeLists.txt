set(TEST_DEPS ${FILECHECK_DEPS})

if (APPLE)
  set (LIBCXX_NAME "libc++.1.dylib")
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set (LIBCXX_NAME "libc++.so.1")
endif ()

# For now, libc++ is not supported on Windows, so tests which rely on libc++
# are disabled
if (NOT WIN32)
  find_library (DEV_LIBCXX
    NAMES ${LIBCXX_NAME}
    HINTS "${LLVM_DIR}/../../../lib"
    NO_DEFAULT_PATH
  )
  if (DEV_LIBCXX STREQUAL "DEV_LIBCXX-NOTFOUND")
    message (FATAL_ERROR "Could not find libc++! Please specify in DEV_LIBCXX")
  endif()
  get_filename_component (DEV_LIBCXX_DIR ${DEV_LIBCXX} DIRECTORY)

  find_path (DEV_LIBCXX_INCLUDES_DIR
    NAMES __libcpp_version
    HINTS "${LLVM_DIR}/../../../include"
    PATH_SUFFIXES "c++/v1"
    NO_DEFAULT_PATH
  )
  if (DEV_LIBCXX_INCLUDES_DIR STREQUAL "DEV_LIBCXX_INCLUDES_DIR-NOTFOUND")
    message (FATAL_ERROR "Could not find libc++ headers! Please specify in DEV_LIBCXX_INCLUDES_DIR")
  endif()
endif (NOT WIN32)

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

add_lit_target (check-dev "Running the Covert C++ Development regression tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${TEST_DEPS}
  ARGS ${TOOLS_TEST_EXTRA_ARGS}
)
set_target_properties (check-dev PROPERTIES FOLDER "Tests")
if (TARGET check)
  add_dependencies (check check-dev)
endif ()
add_dependencies (check-dev Oblivious)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
)
