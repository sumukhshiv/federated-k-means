add_executable (DynLoader
  DynLoader.c
  ${COVERT_TOOLS_INCLUDE_DIR}/NVT/NVTCommon.h
)
target_link_libraries (DynLoader dl NVT)
set_target_properties (DynLoader
  PROPERTIES
  FOLDER "Tools"
  COMPILE_FLAGS -O0 # required to disable inlining
)
covert_set_output_directory (DynLoader
  BINARY_DIR ${COVERT_RUNTIME_OUTPUT_INTDIR}
  LIBRARY_DIR ${COVERT_LIBRARY_OUTPUT_INTDIR}
)

install(TARGETS DynLoader RUNTIME DESTINATION bin)
