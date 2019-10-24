if (DEFINED FILECHECK_DEPS)
  file (DOWNLOAD
    https://raw.githubusercontent.com/llvm-mirror/llvm/master/utils/FileCheck/FileCheck.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/FileCheck.cpp
  )

  add_libtool_utility(FileCheck
    ${CMAKE_CURRENT_BINARY_DIR}/FileCheck.cpp
  )

  target_link_libraries(FileCheck PRIVATE LLVMSupport)
endif (DEFINED FILECHECK_DEPS)
