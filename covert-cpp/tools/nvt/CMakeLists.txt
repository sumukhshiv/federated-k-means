set (SUPPORTED_ARCH_64 "x86_64" "AMD64")
set (SUPPORTED_ARCH_32 "x86")

find_package (DynamoRIO REQUIRED CONFIG)
if ((NOT DEFINED _DynamoRIO_DIR) OR (NOT ${_DynamoRIO_DIR} STREQUAL ${DynamoRIO_DIR}))
  message (STATUS "Found DynamoRIO ${DynamoRIO_VERSION}: ${DynamoRIO_DIR}")
  file (TO_CMAKE_PATH ${DynamoRIO_DIR} DynamoRIO_DIR)
  set (_DynamoRIO_DIR ${DynamoRIO_DIR} CACHE INTERNAL "" FORCE)

  if (("${CMAKE_HOST_SYSTEM_PROCESSOR}" IN_LIST SUPPORTED_ARCH_64))
    find_program (DRRUN_EXECUTABLE drrun
      HINTS "${DynamoRIO_DIR}/../bin64"
    )
  elseif ("${CMAKE_HOST_SYSTEM_PROCESSOR}" IN_LIST SUPPORTED_ARCH_32)
    find_program (DRRUN_EXECUTABLE drrun
      HINTS "${DynamoRIO_DIR}/../bin32"
    )
  else ()
    message (FATAL_ERROR "CPU Architecture \"${CMAKE_HOST_SYSTEM_PROCESSOR}\" unsupported by NVT")
  endif ()

  if ("${DRRUN_EXECUTABLE}" STREQUAL "DRRUN_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Could not find drrun executable")
  endif ()
endif ()

find_package (DrMemoryFramework REQUIRED CONFIG)
if ((NOT DEFINED _DrMemoryFramework_DIR) OR (NOT ${_DrMemoryFramework_DIR} STREQUAL ${DrMemoryFramework_DIR}))
  message (STATUS "Found Dr. Memory ${DrMemoryFramework_VERSION}: ${DrMemoryFramework_DIR}")
  file (TO_CMAKE_PATH ${DrMemoryFramework_DIR} DrMemoryFramework_DIR)
  set (_DrMemoryFramework_DIR ${DrMemoryFramework_DIR} CACHE INTERNAL "" FORCE)
endif ()

include_directories (${COVERT_INCLUDE_SOURCE_DIRECTORY})

add_subdirectory (NVT)
add_subdirectory (DynLoader)
