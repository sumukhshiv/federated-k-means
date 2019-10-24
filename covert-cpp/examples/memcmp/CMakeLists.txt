add_example (memcmp memcmp.cpp memcmp.h main.cpp)

add_custom_target (example-memcmp-run
  COMMAND $<TARGET_FILE:example-memcmp>
  DEPENDS example-memcmp
  COMMENT "Running the Covert C++ memcmp example"
  WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
  USES_TERMINAL
)
set_target_properties (example-memcmp-run
  PROPERTIES
    FOLDER "Examples"
)

if (${BUILD_NVT})
  add_library (example-memcmp-test-high MODULE
    nvt_test.cpp memcmp.cpp
  )
  target_link_libraries (example-memcmp-test-high Covert NVT)
  set_target_properties (example-memcmp-test-high
    PROPERTIES
      FOLDER "Examples/Bin"
      EXCLUDE_FROM_ALL TRUE
      COMPILE_DEFINITIONS "__NO_OUTPUT__;__HIGH__"
  )
  covert_set_output_directory (example-memcmp-test-high
    BINARY_DIR "${COVERT_RUNTIME_OUTPUT_INTDIR}/examples"
    LIBRARY_DIR "${COVERT_LIBRARY_OUTPUT_INTDIR}/examples"
  )
  add_custom_target (example-memcmp-test-high-run
    COMMAND ${DRRUN_EXECUTABLE}
      -c $<TARGET_FILE:NVTClient> -s 8
      -- $<TARGET_FILE:DynLoader> $<TARGET_FILE:example-memcmp-test-high>
    DEPENDS NVT DynLoader example-memcmp-test-high
    COMMENT "Running the high memcmp test (expect: success)"
  )
  set_target_properties (example-memcmp-test-high-run PROPERTIES
    FOLDER "Examples/Depends"
  )

  add_library (example-memcmp-test-low MODULE
    nvt_test.cpp memcmp.cpp
  )
  target_link_libraries (example-memcmp-test-low Covert NVT)
  set_target_properties (example-memcmp-test-low
    PROPERTIES
      FOLDER "Examples/Bin"
      EXCLUDE_FROM_ALL TRUE
      COMPILE_DEFINITIONS "__NO_OUTPUT__"
  )
  covert_set_output_directory (example-memcmp-test-low
    BINARY_DIR "${COVERT_RUNTIME_OUTPUT_INTDIR}/examples"
    LIBRARY_DIR "${COVERT_LIBRARY_OUTPUT_INTDIR}/examples"
  )
  add_custom_target (example-memcmp-test-low-run
    COMMAND ${NOT_PROG} ${DRRUN_EXECUTABLE}
    -c $<TARGET_FILE:NVTClient> -s 8 -f
      -- $<TARGET_FILE:DynLoader> $<TARGET_FILE:example-memcmp-test-low>
    DEPENDS NVT DynLoader example-memcmp-test-low
    COMMENT "Running the low memcmp test (expect: failure)"
  )
  set_target_properties (example-memcmp-test-low-run PROPERTIES
    FOLDER "Examples/Depends"
  )

  add_custom_target (example-memcmp-test DEPENDS
    example-memcmp-test-high-run example-memcmp-test-low-run
  )
  set_target_properties (example-memcmp-test PROPERTIES
    FOLDER "Examples"
  )
endif ()
