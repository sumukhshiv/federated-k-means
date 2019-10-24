if (MSVC)
  set (ALL_COMPILER_OPTS "/Ox")
else ()
  set (ALL_COMPILER_OPTS "-O3")
endif ()
set (NVT_TEST_CXX_FLAGS
  "${ALL_COMPILER_OPTS}"
  CACHE STRING "Flags to use when testing the NVT"
)
separate_arguments (NVT_TEST_CXX_FLAGS)

add_lit_target (check-ni "Running the Covert C++ dynamic noninterference tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS
    DynLoader
    NVTClient
    ${NOT_PROG_DEPS}
  ARGS ${TOOLS_TEST_EXTRA_ARGS}
)
set_target_properties (check-ni PROPERTIES FOLDER "Tests")
add_dependencies (check-ni DynLoader)
if (TARGET check)
  add_dependencies (check check-ni)
endif ()

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

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
)

function (add_ni_test file)
  cmake_parse_arguments (PARSE_ARGV 1 NI_TEST_ARG CREATE_UNIT_TEST "" LINK_LIBRARIES)

  get_filename_component (FILE_NAME ${file} NAME_WE)
  get_filename_component (FILE_EXT ${file} EXT)
  set (TARGET_NAME ni_${FILE_NAME})
  set (TARGET_NAME_TEST ${TARGET_NAME}_test)

  function (make_test)
    # For the NVT tests, we allow custom user-provided flags instead of the
    # global ones.
    set (CMAKE_CXX_FLAGS "")
    set (CMAKE_CXX_FLAGS_DEBUG "")
    set (CMAKE_CXX_FLAGS_RELEASE "")
    set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
    set (CMAKE_CXX_FLAGS_MINSIZEREL "")

    add_library (${TARGET_NAME} MODULE
      ${file}
    )
    target_link_libraries (${TARGET_NAME} NVT ${NI_TEST_ARG_LINK_LIBRARIES})
    target_compile_options (${TARGET_NAME} PUBLIC ${NVT_TEST_CXX_FLAGS})
    get_target_property (SOURCE_FILES ${TARGET_NAME} SOURCES)
    list (GET SOURCE_FILES 0 MAIN_SOURCE_FILE)
    get_filename_component (MAIN_SOURCE_FILE_NAME ${MAIN_SOURCE_FILE} NAME)
    set_target_properties(${TARGET_NAME}
      PROPERTIES
        PREFIX ""
        SUFFIX ".out"
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        LIBRARY_OUTPUT_NAME ${MAIN_SOURCE_FILE_NAME}
        EXCLUDE_FROM_ALL TRUE
        FOLDER "NVT Tests"
    )
    add_dependencies (check-ni ${TARGET_NAME})
  endfunction (make_test)

  make_test ()

  if (NI_TEST_ARG_CREATE_UNIT_TEST)
    set (TARGET_NAME_TEST_RUNTIME _${TARGET_NAME_TEST})
    add_executable (${TARGET_NAME_TEST_RUNTIME} EXCLUDE_FROM_ALL
      ${file}
    )
    target_link_libraries (${TARGET_NAME_TEST_RUNTIME} NVT ${NI_TEST_ARG_LINK_LIBRARIES})
    #target_compile_options (${TARGET_NAME_TEST_RUNTIME} PUBLIC ${NVT_TEST_CXX_FLAGS})
    set_target_properties (${TARGET_NAME_TEST_RUNTIME}
      PROPERTIES
        EXCLUDE_FROM_DEFAULT_BUILD TRUE
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        SUFFIX ""
        COMPILE_DEFINITIONS __TEST__
        FOLDER "NVT Tests"
    )
    add_custom_target (${TARGET_NAME_TEST}
      COMMAND $<TARGET_FILE:_${TARGET_NAME_TEST}>
      DEPENDS _${TARGET_NAME_TEST}
      COMMENT "Running ${TARGET_NAME_TEST}..."
    )
  endif (NI_TEST_ARG_CREATE_UNIT_TEST)
endfunction (add_ni_test)

add_ni_test (ternary.cpp CREATE_UNIT_TEST LINK_LIBRARIES Covert)
add_ni_test (heap.cpp CREATE_UNIT_TEST LINK_LIBRARIES Covert)
add_ni_test (storage.c CREATE_UNIT_TEST)
add_ni_test (CovertO.cpp LINK_LIBRARIES Covert)
add_subdirectory (Oblivious)
add_subdirectory (Algorithm)
