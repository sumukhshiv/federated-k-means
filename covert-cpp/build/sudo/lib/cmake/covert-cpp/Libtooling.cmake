llvm_map_components_to_libnames (llvm_libs
  option
  support
  mcparser
  bitreader
  profiledata
)

if (WIN32)
  # MSVCToolChain.cpp uses version.dll
  set (system_libs version)
endif (WIN32)

set (clang_libs
  clangTooling
  clangToolingCore
  clangFormat
  clangRewrite
  clangFrontend
  clangSerialization
  clangParse
  clangSema
  clangEdit
  clangLex
  clangDriver
  clangAST
  clangAnalysis
  clangBasic
)
if (NOT (${LLVM_VERSION} VERSION_LESS "7.0.0"))
  set (clang_libs ${clang_libs} clangToolingInclusions)
endif ()

set (libtool_libs
  ${clang_libs}
  ${llvm_libs}
  ${system_libs}
)

macro(set_libtool_windows_version_resource_properties name)
  if(DEFINED windows_resource_file)
    set_windows_version_resource_properties(${name} ${windows_resource_file}
      VERSION_STRING ${PACKAGE_VERSION}
      PRODUCT_NAME ${PROJECT_NAME})
  endif()
endmacro()

macro(add_libtool_executable name)
  cmake_parse_arguments(ARG "" "" "DEPENDS" ${ARGN})
  llvm_process_sources(ALL_FILES ${ARG_UNPARSED_ARGUMENTS})

  list(APPEND LIBTOOL_DEPS ${ARG_DEPENDS})
  add_windows_version_resource_file(ALL_FILES ${ALL_FILES})

  if( EXCLUDE_FROM_ALL )
    add_executable(${name} EXCLUDE_FROM_ALL ${ALL_FILES})
  else()
    add_executable(${name} ${ALL_FILES})
  endif()

  if(DEFINED windows_resource_file)
    set_windows_version_resource_properties(${name} ${windows_resource_file})
  endif()

  llvm_update_compile_flags(${name})
  add_link_opts( ${name} )

  # Do not add -Dname_EXPORTS to the command-line when building files in this
  # target. Doing so is actively harmful for the modules build because it
  # creates extra module variants, and not useful because we don't use these
  # macros.
  set_target_properties( ${name} PROPERTIES DEFINE_SYMBOL "" )

  if (LLVM_EXPORTED_SYMBOL_FILE)
    add_llvm_symbol_exports( ${name} ${LLVM_EXPORTED_SYMBOL_FILE} )
  endif(LLVM_EXPORTED_SYMBOL_FILE)

  if (LLVM_LINK_LLVM_DYLIB AND NOT ARG_DISABLE_LLVM_LINK_LLVM_DYLIB)
    set(USE_SHARED USE_SHARED)
  endif()

  set_target_properties(${name} PROPERTIES FOLDER "Tools")
  set_libtool_windows_version_resource_properties( ${name} )
  if (NOT EXCLUDE_FROM_ALL)
    if (APPLE AND UNIX)
      install (CODE "execute_process(
          COMMAND ${CMAKE_COMMAND} -E create_symlink
            ${CMAKE_BINARY_DIR}/bin/${name}
            ${CMAKE_INSTALL_PREFIX}/bin/${name}
          )
        message(STATUS \"Update symlink: ${CMAKE_INSTALL_PREFIX}/bin/${name} -> ${CMAKE_BINARY_DIR}/bin/${name}\")"
      )
    else ()
      install(TARGETS ${name} RUNTIME DESTINATION bin)
    endif ()
  endif (NOT EXCLUDE_FROM_ALL)

  set(EXCLUDE_FROM_ALL OFF)
  covert_set_output_directory(${name} BINARY_DIR ${COVERT_RUNTIME_OUTPUT_INTDIR} LIBRARY_DIR ${COVERT_LIBRARY_OUTPUT_INTDIR})
  if (LIBTOOL_DEPS)
    add_dependencies(${name} ${LIBTOOL_DEPS})
  endif (LIBTOOL_DEPS)
endmacro(add_libtool_executable)

# This is a macro that is used to create targets for executables that are needed
# for development, but that are not intended to be installed.
macro(add_libtool_utility name)
  set(EXCLUDE_FROM_ALL ON)

  add_libtool_executable(${name} ${ARGN})
  set_target_properties(${name} PROPERTIES FOLDER "Utils")
endmacro(add_libtool_utility name)
