if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  # FIXME: This will no longer be needed once the Ubuntu/Debian llvm package is fixed
  add_subdirectory(FileCheck)
  add_subdirectory(not)
endif ()
