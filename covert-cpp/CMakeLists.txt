cmake_minimum_required(VERSION 3.8.2)

set (PROJECT_NAME covert-cpp)

# Version Number
set(${PROJECT_NAME}_VERSION_MAJOR 0)
set(${PROJECT_NAME}_VERSION_MINOR 1)
set(${PROJECT_NAME}_VERSION_PATCH 0)
set(${PROJECT_NAME}_VERSION_TWEAK 0)

if (NOT PACKAGE_VERSION)
  set(PACKAGE_VERSION
    "${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}.${${PROJECT_NAME}_VERSION_PATCH}.${${PROJECT_NAME}_VERSION_TWEAK}")
endif()
message (STATUS "Covert C++ toolchain version ${PACKAGE_VERSION}")
set (COVERT_CXX_STANDARD 17 CACHE STRING "C++ standard to use for testing and examples")
message (STATUS "Covert C++: using the C++${COVERT_CXX_STANDARD} standard")

project(${PROJECT_NAME} C CXX)

set (COVERTCPP_MODULE_DIR "lib/cmake/${PROJECT_NAME}/")
set (COVERTCPP_INCLUDE_DIR "include/${PROJECT_NAME}/")
set (COVERTCPP_BINARY_DIR "bin/")
include (CMakePackageConfigHelpers)
set (COVERT_BUILD_MODULE_DIR ${CMAKE_BINARY_DIR}/lib/cmake/${PROJECT_NAME}/)
write_basic_package_version_file (
  "${COVERT_BUILD_MODULE_DIR}/${PROJECT_NAME}-config-version.cmake"
  VERSION ${PACKAGE_VERSION}
  COMPATIBILITY AnyNewerVersion
)
configure_package_config_file (
  "${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in"
  "${COVERT_BUILD_MODULE_DIR}/${PROJECT_NAME}-config.cmake"
  INSTALL_DESTINATION ${COVERTCPP_MODULE_DIR}
  PATH_VARS
    COVERTCPP_MODULE_DIR
    COVERTCPP_INCLUDE_DIR
    COVERTCPP_BINARY_DIR
)
install (
  FILES
    "${PROJECT_BINARY_DIR}/lib/cmake/${PROJECT_NAME}/${PROJECT_NAME}-config-version.cmake"
    "${PROJECT_BINARY_DIR}/lib/cmake/${PROJECT_NAME}/${PROJECT_NAME}-config.cmake"
  DESTINATION ${COVERTCPP_MODULE_DIR}
  COMPONENT Development
)

if (MSVC)
  enable_language (ASM_MASM)
endif (MSVC)

# enable folders
set_property (GLOBAL PROPERTY USE_FOLDERS ON)

set (COVERT_CMAKE_DIR "${PROJECT_SOURCE_DIR}/cmake")
list (APPEND CMAKE_MODULE_PATH ${COVERT_CMAKE_DIR})

set (COVERT_INCLUDE_SOURCE_DIRECTORY "${PROJECT_SOURCE_DIR}/include/")
set (COVERT_INCLUDE_BINARY_DIRECTORY "${PROJECT_BINARY_DIR}/include/")

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "No build type selected, default to Debug")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

set(COVERT_RUNTIME_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/bin)
set(COVERT_LIBRARY_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${COVERT_LIBRARY_OUTPUT_INTDIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${COVERT_LIBRARY_OUTPUT_INTDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${COVERT_RUNTIME_OUTPUT_INTDIR})

# Set each output directory according to ${CMAKE_CONFIGURATION_TYPES}.
# Note: Don't set variables CMAKE_*_OUTPUT_DIRECTORY any more,
# or a certain builder, for eaxample, msbuild.exe, would be confused.
function(covert_set_output_directory target)
  cmake_parse_arguments(ARG "" "BINARY_DIR;LIBRARY_DIR" "" ${ARGN})

  # module_dir -- corresponding to LIBRARY_OUTPUT_DIRECTORY.
  # It affects output of add_library(MODULE).
  if(WIN32 OR CYGWIN)
    # DLL platform
    set(module_dir ${ARG_BINARY_DIR})
  else()
    set(module_dir ${ARG_LIBRARY_DIR})
  endif()

  if(NOT "${CMAKE_CFG_INTDIR}" STREQUAL ".")
    foreach(build_mode ${CMAKE_CONFIGURATION_TYPES})
      string(TOUPPER "${build_mode}" CONFIG_SUFFIX)
      if(ARG_BINARY_DIR)
        string(REPLACE ${CMAKE_CFG_INTDIR} ${build_mode} bi ${ARG_BINARY_DIR})
        set_target_properties(${target} PROPERTIES "RUNTIME_OUTPUT_DIRECTORY_${CONFIG_SUFFIX}" ${bi})
      endif()
      if(ARG_LIBRARY_DIR)
        string(REPLACE ${CMAKE_CFG_INTDIR} ${build_mode} li ${ARG_LIBRARY_DIR})
        set_target_properties(${target} PROPERTIES "ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_SUFFIX}" ${li})
      endif()
      if(module_dir)
        string(REPLACE ${CMAKE_CFG_INTDIR} ${build_mode} mi ${module_dir})
        set_target_properties(${target} PROPERTIES "LIBRARY_OUTPUT_DIRECTORY_${CONFIG_SUFFIX}" ${mi})
      endif()
    endforeach()
  else()
    if(ARG_BINARY_DIR)
      set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${ARG_BINARY_DIR})
    endif()
    if(ARG_LIBRARY_DIR)
      set_target_properties(${target} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${ARG_LIBRARY_DIR})
    endif()
    if(module_dir)
      set_target_properties(${target} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${module_dir})
    endif()
  endif()
endfunction()

find_package(PythonInterp 2.7 REQUIRED)

function (math_log output x base)
  set (LOG_SCRIPT "exec(\"from math import log\\nprint(int(log(${x},${base})))\")")
  execute_process (
    COMMAND ${PYTHON_EXECUTABLE} -c ${LOG_SCRIPT}
    RESULT_VARIABLE LOG_RESULT
    OUTPUT_VARIABLE LOG_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if (${LOG_RESULT})
    message (FATAL_ERROR "Could not compute log(x, b) using Python")
  else ()
    set (${output} ${LOG_OUTPUT} PARENT_SCOPE)
  endif ()
endfunction (math_log)

if (NOT DEFINED MEMORY_SIDECHANNEL_BITS)
  # Determine the CPU's cache line width
  message (STATUS "Detecting host CPU cache block size")
  set (TARGET_CPU_CACHE_BLOCK_SIZE 64)
  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    execute_process (
      COMMAND getconf LEVEL1_DCACHE_LINESIZE
      OUTPUT_VARIABLE TARGET_CPU_CACHE_BLOCK_SIZE_
      RESULT_VARIABLE CACHE_RESULT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  elseif (APPLE)
    execute_process (
      COMMAND sysctl hw.cachelinesize
      OUTPUT_VARIABLE TARGET_CPU_CACHE_BLOCK_SIZE_
      RESULT_VARIABLE CACHE_RESULT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    string (REGEX MATCH "[0-9]+" TARGET_CPU_CACHE_BLOCK_SIZE_ ${TARGET_CPU_CACHE_BLOCK_SIZE_})
  elseif (WIN32)
    message (STATUS "On Windows systems, assume cache block size of 64 bytes")
    set (TARGET_CPU_CACHE_BLOCK_SIZE_ 64)
    set (CACHE_RESULT 0)
  endif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  if (NOT ${CACHE_RESULT})
    message (STATUS "Detecting host CPU cache block size - Success (${TARGET_CPU_CACHE_BLOCK_SIZE_} bytes)")
    message (STATUS "\
  Note: If building Covert C++ for another platform, manually\n\
           set TARGET_CPU_CACHE_BLOCK_SIZE for that platform")
  else ()
    set (TARGET_CPU_CACHE_BLOCK_SIZE ${TARGET_CPU_CACHE_BLOCK_SIZE_})
    message (WARNING "Could not detect CPU cache block size")
  endif ()
  math_log (SIDECHANNEL_BITS ${TARGET_CPU_CACHE_BLOCK_SIZE} 2)
  message (STATUS "Setting MEMORY_SIDECHANNEL_BITS to ${SIDECHANNEL_BITS}")
  set (MEMORY_SIDECHANNEL_BITS ${SIDECHANNEL_BITS} CACHE STRING
    "Granulary of memory side channel protections and analysis (in bits)"
  )
endif (NOT DEFINED MEMORY_SIDECHANNEL_BITS)

option (ENABLE_DOXYGEN "adds a target 'doxygen' which builds the documentation")
if (ENABLE_DOXYGEN)
  add_subdirectory(docs)
endif (ENABLE_DOXYGEN)
add_subdirectory(examples)
add_subdirectory(include)
include (CovertCXXCompilerTests)
add_subdirectory(lib)
add_subdirectory(cmake)

option (BUILD_COVERT_TOOLCHAIN "Build the Covert C++ toolchain" ON)
if (BUILD_COVERT_TOOLCHAIN)
  # Covert C++ toolchain and test suites require an LLVM installation
  set (LLVM_MIN_REQUIRED_VERSION "5.0.0")
  find_package (LLVM REQUIRED CONFIG)
  file (TO_CMAKE_PATH ${LLVM_DIR} LLVM_DIR)
  set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
    ${LLVM_LIBRARY_DIRS}/cmake/llvm/
  )
  set (LLVM_INSTALL_DIR "${LLVM_DIR}/../../../")
  if ((NOT DEFINED _LLVM_DIR) OR (NOT ${_LLVM_DIR} STREQUAL ${LLVM_DIR}))
    if (${LLVM_VERSION} VERSION_LESS ${LLVM_MIN_REQUIRED_VERSION})
      message (FATAL_ERROR "Found LLVM version ${LLVM_VERSION}. Version >=${LLVM_MIN_REQUIRED_VERSION} required")
    else ()
      message (STATUS "Found LLVM version ${LLVM_PACKAGE_VERSION}: ${LLVM_DIR}")
      set (_LLVM_DIR ${LLVM_DIR} CACHE INTERNAL "" FORCE)
    endif ()
  endif ()

  add_subdirectory (tools)
  add_subdirectory (test)
endif ()
