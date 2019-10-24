add_custom_target (example-all)
set_target_properties(example-all PROPERTIES FOLDER "Examples")

if (NOT (MSVC OR XCODE))
  add_custom_target (examples DEPENDS example-all)
endif ()

macro (add_example name)
  set (options LIBRARY)
  cmake_parse_arguments (ADD_EXAMPLE "${options}" "" "" ${ARGN})
  if (${ADD_EXAMPLE_LIBRARY})
    add_library (example-${name} SHARED ${ADD_EXAMPLE_UNPARSED_ARGUMENTS})
  else ()
    add_executable (example-${name} ${ADD_EXAMPLE_UNPARSED_ARGUMENTS})
  endif ()
  target_link_libraries (example-${name} Covert)
  set_target_properties (example-${name} PROPERTIES
    FOLDER "Examples/Bin"
    EXCLUDE_FROM_ALL TRUE
  )
  covert_set_output_directory (example-${name}
    BINARY_DIR ${COVERT_RUNTIME_OUTPUT_INTDIR}/examples
    LIBRARY_DIR ${COVERT_LIBRARY_OUTPUT_INTDIR}/examples
  )
  add_dependencies (example-all example-${name})
endmacro ()

add_subdirectory (memcmp)
add_subdirectory (chi2)
add_subdirectory (knn)
