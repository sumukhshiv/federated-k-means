configure_file (CovertCXXCompilerTests.cmake ${COVERT_BUILD_MODULE_DIR}/CovertCXXCompilerTests.cmake COPYONLY)
configure_file (Libtooling.cmake ${COVERT_BUILD_MODULE_DIR}/Libtooling.cmake COPYONLY)
install (
  FILES
    CovertCXXCompilerTests.cmake
    Libtooling.cmake
  DESTINATION ${COVERTCPP_MODULE_DIR}
  COMPONENT Development
)
