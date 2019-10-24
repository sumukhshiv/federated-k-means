add_library (NVTClient
  MODULE
  NVTMain.c
  NVTOptions.cpp
  MD5.c

  # headers
  NVTOptions.h
  MD5.h
)
target_link_libraries (NVTClient NVT)
set_target_properties (NVTClient PROPERTIES FOLDER "Libraries")
if (NOT WIN32)
target_compile_features (NVTClient PRIVATE c_std_11)
endif (NOT WIN32)
target_compile_features (NVTClient PRIVATE cxx_uniform_initialization)
covert_set_output_directory (NVTClient
  BINARY_DIR ${COVERT_RUNTIME_OUTPUT_INTDIR}
  LIBRARY_DIR ${COVERT_LIBRARY_OUTPUT_INTDIR}
)

install (TARGETS NVTClient
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
)

# If the DynamoRIO installation does not include Dr. Memory, we need to use
# relative paths to locate the Dr. Memory libraries
if (NOT EXISTS "${DynamoRIO_DIR}/../drmemory/drmf")
  set (DynamoRIO_RPATH ON)
else ()
  set (DynamoRIO_RPATH OFF)
endif ()

configure_DynamoRIO_client (NVTClient)
use_DynamoRIO_extension (NVTClient drmgr)
use_DynamoRIO_extension (NVTClient drutil)
use_DynamoRIO_extension (NVTClient droption)
use_DynamoRIO_extension (NVTClient drreg)
use_DynamoRIO_extension (NVTClient drsyms)
use_DynamoRIO_extension (NVTClient drwrap)
use_DynamoRIO_extension (NVTClient drfuzz)
