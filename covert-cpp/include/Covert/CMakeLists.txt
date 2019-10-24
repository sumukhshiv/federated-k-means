add_library (Covert INTERFACE)
target_compile_features (Covert INTERFACE cxx_std_17)
target_link_libraries (Covert INTERFACE ObliviousCXX)
target_include_directories (Covert
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${COVERTCPP_INCLUDE_DIR}/Covert>
)
install (TARGETS Covert
  EXPORT CovertTargets
)
install (
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/cov_algorithm.h
    ${CMAKE_CURRENT_SOURCE_DIR}/__covert_functions.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Covert.h
    ${CMAKE_CURRENT_SOURCE_DIR}/__covert_helpers.h
    ${CMAKE_CURRENT_SOURCE_DIR}/__covert_impl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/__covert_logging.h
    ${CMAKE_CURRENT_SOURCE_DIR}/CovertSTL.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cov_iterator.h
    ${CMAKE_CURRENT_SOURCE_DIR}/SE.h
    ${CMAKE_CURRENT_SOURCE_DIR}/__covert_o_impl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/CovertO.h
    DESTINATION ${COVERTCPP_INCLUDE_DIR}/Covert/
)
export (EXPORT CovertTargets
  FILE ${COVERT_BUILD_MODULE_DIR}/CovertTargets.cmake
)
install (
  EXPORT CovertTargets
  DESTINATION ${COVERTCPP_MODULE_DIR}
  EXPORT_LINK_INTERFACE_LIBRARIES
)
