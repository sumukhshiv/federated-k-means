if (DEFINED NOT_PROG_DEPS)
  file (DOWNLOAD
    https://raw.githubusercontent.com/llvm-mirror/llvm/master/utils/not/not.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/not.cpp
  )

  add_libtool_utility(not
    ${CMAKE_CURRENT_BINARY_DIR}/not.cpp
  )

  target_link_libraries(not PRIVATE LLVMSupport)
endif (DEFINED NOT_PROG_DEPS)
