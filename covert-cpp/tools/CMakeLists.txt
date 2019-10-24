set (COVERT_TOOLS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories (${COVERT_TOOLS_INCLUDE_DIR})

if (NOT APPLE) # DynamoRIO is not (yet) supported on macOS
  option (BUILD_NVT "Build the NVT and enable NVT tests")
  if (${BUILD_NVT})
    add_subdirectory (nvt)
  endif ()
endif (NOT APPLE)

# LLVM-based refactoring tools below
include (Libtooling)
set (LLVM_ENABLE_WARNINGS ON CACHE BOOL "Libtools: enable all warnings")
set (LLVM_ENABLE_PEDANTIC ON CACHE BOOL "Libtools: enable pedantic warnings")
set (LLVM_ENABLE_WERROR OFF CACHE BOOL "Libtools: treat warnings as errors")

if (LLVM_BUILD_MAIN_SRC_DIR) # configured from source
  include_directories(
    ${LLVM_BUILD_MAIN_SRC_DIR}/include
    ${LLVM_BUILD_MAIN_SRC_DIR}/tools/clang/include
    ${LLVM_BUILD_BINARY_DIR}/include
    ${LLVM_BUILD_BINARY_DIR}/tools/clang/include
    )
else () # configured from an LLVM installation
  include_directories(
    ${LLVM_INCLUDE_DIRS}
    )
endif()

link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})
include (HandleLLVMOptions)
include (AddLLVM)

add_subdirectory(lib)
add_subdirectory(c2cpp)
add_subdirectory(cpp2covert)
add_subdirectory(utils)

install (PROGRAMS run-refactor.py DESTINATION bin)
