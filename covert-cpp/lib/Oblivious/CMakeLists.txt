set (_OBLIVIOUS_HEADER_FILES
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/Oblivious.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/__oblivious_impl.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/__o_impl.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/O.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/omemory.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/oarray.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/ovector.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/odeque.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/oqueue.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/ostack.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/olist.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/oforward_list.h
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/oalgorithm.h
)

set (OBLIVIOUS_BUILD_HEADER_FILES
  ${_OBLIVIOUS_HEADER_FILES}
  ${COVERT_INCLUDE_BINARY_DIRECTORY}/Oblivious/ObliviousDefs.h
)

set (OBLIVIOUS_SOURCE_HEADER_FILES
  ${_OBLIVIOUS_HEADER_FILES}
  ${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/ObliviousDefs.h.in
)

if (MSVC)
  set (OBLIVIOUS_ASM Oblivious.asm)
  set (OBLIVIOUS_MODULE_DEF ${CMAKE_CURRENT_SOURCE_DIR}/Oblivious.def)
endif (MSVC)
add_library (Oblivious SHARED
  Oblivious.c
  Allocator.cpp
  ${OBLIVIOUS_ASM}

  # header files
  ${OBLIVIOUS_SOURCE_HEADER_FILES}
)
target_include_directories (Oblivious
  PUBLIC $<BUILD_INTERFACE:${COVERT_INCLUDE_SOURCE_DIRECTORY}/Oblivious/>
  PUBLIC $<BUILD_INTERFACE:${COVERT_INCLUDE_BINARY_DIRECTORY}/Oblivious/>
  INTERFACE $<INSTALL_INTERFACE:${COVERTCPP_INCLUDE_DIR}/Oblivious/>
)
if (MSVC)
  set_target_properties (Oblivious PROPERTIES
    LINK_FLAGS "/DEF:${OBLIVIOUS_MODULE_DEF}"
    LINK_DEPENDS ${OBLIVIOUS_MODULE_DEF}
  )
endif (MSVC)
option (LIBOBLIVIOUS_USE_VPGATHER
  "Use the vpgatherdd instruction to perform oblivious memory accesses"
  ON
)
if (${LIBOBLIVIOUS_USE_VPGATHER})
  target_compile_definitions (Oblivious PRIVATE __LIBOBLIVIOUS_USE_VPGATHER__)
endif ()
target_compile_options (Oblivious INTERFACE ${AVX2_FLAG})
set_source_files_properties (Oblivious.c PROPERTIES COMPILE_FLAGS ${AVX2_FLAG})
target_compile_features (Oblivious PRIVATE cxx_std_17)
covert_set_output_directory (Oblivious
  BINARY_DIR ${COVERT_RUNTIME_OUTPUT_INTDIR}
  LIBRARY_DIR ${COVERT_LIBRARY_OUTPUT_INTDIR}
)
set_target_properties (Oblivious PROPERTIES FOLDER "Libraries")

add_library (ObliviousCXX INTERFACE)
target_compile_features (ObliviousCXX INTERFACE cxx_std_17)
target_link_libraries (ObliviousCXX INTERFACE Oblivious)
target_compile_options (ObliviousCXX INTERFACE ${AVX2_FLAG})

install (TARGETS Oblivious ObliviousCXX
  EXPORT ObliviousTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
)
export (EXPORT ObliviousTargets
  FILE ${COVERT_BUILD_MODULE_DIR}/ObliviousTargets.cmake
)
install (EXPORT ObliviousTargets
  FILE ObliviousTargets.cmake
  DESTINATION ${COVERTCPP_MODULE_DIR}
  EXPORT_LINK_INTERFACE_LIBRARIES
)
install (
  FILES ${OBLIVIOUS_BUILD_HEADER_FILES}
  DESTINATION ${COVERTCPP_INCLUDE_DIR}/Oblivious/
)