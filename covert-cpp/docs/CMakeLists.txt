# add a target to generate API documentation with Doxygen
set (DOXYGEN_VERSION_MIN "1.8.0")
find_package(Doxygen MODULE REQUIRED)
if (${DOXYGEN_VERSION} VERSION_LESS ${DOXYGEN_VERSION_MIN})
  message (FATAL_ERROR "Found doxygen ${DOXYGEN_VERSION}. Version >=${DOXYGEN_VERSION_MIN} required.")
endif ()

set (COVERT_DOCUMENTED_HEADERS "\\
  ${PROJECT_SOURCE_DIR}/include/Covert/Covert.h \\
  ${PROJECT_SOURCE_DIR}/include/Covert/CovertO.h \\
  ${PROJECT_SOURCE_DIR}/include/Covert/SE.h \\
  ${PROJECT_SOURCE_DIR}/include/Covert/CovertSTL.h \\
  ${PROJECT_SOURCE_DIR}/include/Covert/cov_algorithm.h \\
  ${PROJECT_SOURCE_DIR}/include/Covert/cov_iterator.h \\"
)

set (OBLIVIOUS_DOCUMENTED_HEADERS "\\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/Oblivious.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/O.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/omemory.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/oarray.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/ovector.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/odeque.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/oalgorithm.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/olist.h \\
  ${PROJECT_SOURCE_DIR}/include/Oblivious/oforward_list.h \\"
)

set (DOXYGEN_INPUT "\\
  ${PROJECT_SOURCE_DIR}/README.md \\
  ${PROJECT_SOURCE_DIR}/examples/examples.h \\
  ${PROJECT_SOURCE_DIR}/examples/chi2 \\
  ${PROJECT_SOURCE_DIR}/examples/knn \\
  ${PROJECT_SOURCE_DIR}/examples/memcmp \\
  ${PROJECT_SOURCE_DIR}/include/NVT \\
  ${PROJECT_SOURCE_DIR}/lib/Oblivious \\
  ${PROJECT_SOURCE_DIR}/tools/include/ \\
  ${PROJECT_SOURCE_DIR}/tools/c2cpp/ \\
  ${PROJECT_SOURCE_DIR}/tools/cpp2covert/ \\
  ${PROJECT_SOURCE_DIR}/tools/nvt/ \\
  ${PROJECT_SOURCE_DIR}/tools/lib/Diagnostic/ \\
  ${PROJECT_SOURCE_DIR}/docs/ \\
  ${OBLIVIOUS_DOCUMENTED_HEADERS}
  ${COVERT_DOCUMENTED_HEADERS}"
)

set (DOXYGEN_PREDEFINED "\\
  __cplusplus= \\
  __declspec(x)= \\
  __attribute__(x)= \\
  NVT_TEST_INIT(n)=NVT_test_init1 \\
  NVT_TEST_BEGIN(n)=NVT_test_begin1"
)

set (DOXYGEN_EXPAND_AS_DEFINED "\\
  GENERATE_COVERT_FUNCTIONS \\
  COVERT_TO_PRIMITIVE \\
  COVERT_GUARD \\
  COVERT_LABEL_CAST \\
  COVERT_NAMED_CAST \\
  COVERT_OPS \\"
)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/doxygen.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/doxygen.cfg
  @ONLY
)

add_custom_target (doxygen
  ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/doxygen.cfg
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMENT "Generating documentation with Doxygen" VERBATIM
)
