# Install script for directory: /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/sudo")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/covert-cpp/Covert" TYPE FILE FILES
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/cov_algorithm.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/__covert_functions.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/Covert.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/__covert_helpers.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/__covert_impl.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/__covert_logging.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/CovertSTL.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/cov_iterator.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/SE.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/__covert_o_impl.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include/Covert/CovertO.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/CovertTargets.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/CovertTargets.cmake"
         "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/include/Covert/CMakeFiles/Export/lib/cmake/covert-cpp/CovertTargets.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/CovertTargets-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/CovertTargets.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp" TYPE FILE FILES "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/include/Covert/CMakeFiles/Export/lib/cmake/covert-cpp/CovertTargets.cmake")
endif()

