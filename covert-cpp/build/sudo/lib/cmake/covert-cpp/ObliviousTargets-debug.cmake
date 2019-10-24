#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Oblivious" for configuration "Debug"
set_property(TARGET Oblivious APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(Oblivious PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libOblivious.so"
  IMPORTED_SONAME_DEBUG "libOblivious.so"
  )

list(APPEND _IMPORT_CHECK_TARGETS Oblivious )
list(APPEND _IMPORT_CHECK_FILES_FOR_Oblivious "${_IMPORT_PREFIX}/lib/libOblivious.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
