# Install script for directory: /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious

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
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libOblivious.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libOblivious.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libOblivious.so"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/libOblivious.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libOblivious.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libOblivious.so")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libOblivious.so")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/ObliviousTargets.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/ObliviousTargets.cmake"
         "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious/CMakeFiles/Export/lib/cmake/covert-cpp/ObliviousTargets.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/ObliviousTargets-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp/ObliviousTargets.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp" TYPE FILE FILES "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious/CMakeFiles/Export/lib/cmake/covert-cpp/ObliviousTargets.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/covert-cpp" TYPE FILE FILES "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious/CMakeFiles/Export/lib/cmake/covert-cpp/ObliviousTargets-debug.cmake")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/covert-cpp/Oblivious" TYPE FILE FILES
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/Oblivious.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/__oblivious_impl.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/__o_impl.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/O.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/omemory.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/oarray.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/ovector.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/odeque.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/oqueue.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/ostack.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/olist.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/oforward_list.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/include//Oblivious/oalgorithm.h"
    "/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/include//Oblivious/ObliviousDefs.h"
    )
endif()

