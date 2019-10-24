add_custom_command (
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/iris.data
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/download.cmake
)
add_custom_target (_download_iris_data
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/iris.data
)
set_target_properties (_download_iris_data PROPERTIES
  FOLDER "Examples/Depends"
)

add_example (knn LIBRARY knn.cpp knn.h)
set_target_properties (example-knn
  PROPERTIES
    OUTPUT_NAME "KNN"
)
add_dependencies (example-knn _download_iris_data)
add_custom_target (example-knn-run
  COMMAND ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/main.py
    ${CMAKE_CURRENT_BINARY_DIR}/iris.data
    $<TARGET_FILE:example-knn>
  DEPENDS example-knn
  COMMENT "Running kNN over iris.data"
  USES_TERMINAL
)
set_target_properties (example-knn-run
  PROPERTIES
    FOLDER "Examples"
)

add_example (oblivious-knn LIBRARY oblivious_knn.cpp knn.h)
set_target_properties (example-oblivious-knn
  PROPERTIES
    OUTPUT_NAME "ObliviousKNN"
)
add_dependencies (example-oblivious-knn _download_iris_data)
add_custom_target (example-oblivious-knn-run
  COMMAND ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/main.py
    ${CMAKE_CURRENT_BINARY_DIR}/iris.data
    $<TARGET_FILE:example-oblivious-knn>
  DEPENDS example-oblivious-knn
  WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
  COMMENT "Running Oblivious kNN over iris.data"
  USES_TERMINAL
)
set_target_properties (example-oblivious-knn-run
  PROPERTIES
    FOLDER "Examples"
)

add_example (covert-knn LIBRARY covert_knn.cpp knn.h)
set_target_properties (example-covert-knn
  PROPERTIES
    OUTPUT_NAME "CovertKNN"
)
add_dependencies (example-covert-knn _download_iris_data)
add_custom_target (example-covert-knn-run
  COMMAND ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/main.py
    ${CMAKE_CURRENT_BINARY_DIR}/iris.data
    $<TARGET_FILE:example-covert-knn>
  DEPENDS example-covert-knn
  WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
  COMMENT "Running Covert kNN over iris.data"
  USES_TERMINAL
)
set_target_properties (example-covert-knn-run
  PROPERTIES
    FOLDER "Examples"
)

if (${BUILD_NVT})
  add_library (example-knn-test MODULE knn_test.c)
  target_link_libraries (example-knn-test example-knn NVT)
  set_target_properties (example-knn-test
    PROPERTIES
      PREFIX ""
      FOLDER "Examples/Bin"
      EXCLUDE_FROM_ALL TRUE
  )
  covert_set_output_directory (example-knn-test
    BINARY_DIR "${COVERT_RUNTIME_OUTPUT_INTDIR}/examples"
    LIBRARY_DIR "${COVERT_LIBRARY_OUTPUT_INTDIR}/examples"
  )
  add_custom_target (example-knn-test-run
    COMMAND ${NOT_PROG} ${DRRUN_EXECUTABLE}
      -c $<TARGET_FILE:NVTClient> -c ${MEMORY_SIDECHANNEL_BITS} -b -s 256
      -- $<TARGET_FILE:DynLoader> $<TARGET_FILE:example-knn-test>
    DEPENDS NVT DynLoader example-knn-test
    COMMENT "Running the Oblivious k-NN noninterference test (expect: failure)"
  )
  set_target_properties (example-knn-test-run PROPERTIES
    FOLDER "Examples"
  )

  add_library (example-oblivious-knn-test MODULE knn_test.c)
  target_link_libraries (example-oblivious-knn-test example-oblivious-knn NVT)
  set_target_properties (example-oblivious-knn-test
    PROPERTIES
      PREFIX ""
      FOLDER "Examples/Bin"
      EXCLUDE_FROM_ALL TRUE
  )
  covert_set_output_directory (example-oblivious-knn-test
    BINARY_DIR "${COVERT_RUNTIME_OUTPUT_INTDIR}/examples"
    LIBRARY_DIR "${COVERT_LIBRARY_OUTPUT_INTDIR}/examples"
  )
  add_custom_target (example-oblivious-knn-test-run
    COMMAND ${DRRUN_EXECUTABLE}
      -c $<TARGET_FILE:NVTClient> -c ${MEMORY_SIDECHANNEL_BITS} -b -s 256
      -- $<TARGET_FILE:DynLoader> $<TARGET_FILE:example-oblivious-knn-test>
    DEPENDS NVT DynLoader example-oblivious-knn-test
    COMMENT "Running the Oblivious k-NN noninterference test (expect: success)"
  )
  set_target_properties (example-oblivious-knn-test-run PROPERTIES
    FOLDER "Examples"
  )

  add_library (example-covert-knn-test MODULE knn_test.c)
  target_link_libraries (example-covert-knn-test example-covert-knn NVT)
  set_target_properties (example-covert-knn-test
    PROPERTIES
      PREFIX ""
      FOLDER "Examples/Bin"
      EXCLUDE_FROM_ALL TRUE
  )
  covert_set_output_directory (example-covert-knn-test
    BINARY_DIR "${COVERT_RUNTIME_OUTPUT_INTDIR}/examples"
    LIBRARY_DIR "${COVERT_LIBRARY_OUTPUT_INTDIR}/examples"
  )
  add_custom_target (example-covert-knn-test-run
    COMMAND ${DRRUN_EXECUTABLE}
      -c $<TARGET_FILE:NVTClient> -c ${MEMORY_SIDECHANNEL_BITS} -b -s 256
      -- $<TARGET_FILE:DynLoader> $<TARGET_FILE:example-covert-knn-test>
    DEPENDS NVT DynLoader example-covert-knn-test
    COMMENT "Running the Covert k-NN noninterference test (expect: success)"
  )
  set_target_properties (example-covert-knn-test-run PROPERTIES
    FOLDER "Examples"
  )
endif (${BUILD_NVT})
