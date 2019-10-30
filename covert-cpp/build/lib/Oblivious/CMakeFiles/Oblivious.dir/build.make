# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build

# Include any dependencies generated for this target.
include lib/Oblivious/CMakeFiles/Oblivious.dir/depend.make

# Include the progress variables for this target.
include lib/Oblivious/CMakeFiles/Oblivious.dir/progress.make

# Include the compile flags for this target's objects.
include lib/Oblivious/CMakeFiles/Oblivious.dir/flags.make

lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o: lib/Oblivious/CMakeFiles/Oblivious.dir/flags.make
lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o: ../lib/Oblivious/Oblivious.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o"
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mavx2 -o CMakeFiles/Oblivious.dir/Oblivious.c.o   -c /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious/Oblivious.c

lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Oblivious.dir/Oblivious.c.i"
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mavx2 -E /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious/Oblivious.c > CMakeFiles/Oblivious.dir/Oblivious.c.i

lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Oblivious.dir/Oblivious.c.s"
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mavx2 -S /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious/Oblivious.c -o CMakeFiles/Oblivious.dir/Oblivious.c.s

lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.requires:

.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.requires

lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.provides: lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.requires
	$(MAKE) -f lib/Oblivious/CMakeFiles/Oblivious.dir/build.make lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.provides.build
.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.provides

lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.provides.build: lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o


lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o: lib/Oblivious/CMakeFiles/Oblivious.dir/flags.make
lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o: ../lib/Oblivious/Allocator.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o"
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Oblivious.dir/Allocator.cpp.o -c /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious/Allocator.cpp

lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Oblivious.dir/Allocator.cpp.i"
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious/Allocator.cpp > CMakeFiles/Oblivious.dir/Allocator.cpp.i

lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Oblivious.dir/Allocator.cpp.s"
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious/Allocator.cpp -o CMakeFiles/Oblivious.dir/Allocator.cpp.s

lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.requires:

.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.requires

lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.provides: lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.requires
	$(MAKE) -f lib/Oblivious/CMakeFiles/Oblivious.dir/build.make lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.provides.build
.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.provides

lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.provides.build: lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o


# Object files for target Oblivious
Oblivious_OBJECTS = \
"CMakeFiles/Oblivious.dir/Oblivious.c.o" \
"CMakeFiles/Oblivious.dir/Allocator.cpp.o"

# External object files for target Oblivious
Oblivious_EXTERNAL_OBJECTS =

lib/libOblivious.so: lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o
lib/libOblivious.so: lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o
lib/libOblivious.so: lib/Oblivious/CMakeFiles/Oblivious.dir/build.make
lib/libOblivious.so: lib/Oblivious/CMakeFiles/Oblivious.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX shared library ../libOblivious.so"
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Oblivious.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
lib/Oblivious/CMakeFiles/Oblivious.dir/build: lib/libOblivious.so

.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/build

lib/Oblivious/CMakeFiles/Oblivious.dir/requires: lib/Oblivious/CMakeFiles/Oblivious.dir/Oblivious.c.o.requires
lib/Oblivious/CMakeFiles/Oblivious.dir/requires: lib/Oblivious/CMakeFiles/Oblivious.dir/Allocator.cpp.o.requires

.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/requires

lib/Oblivious/CMakeFiles/Oblivious.dir/clean:
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious && $(CMAKE_COMMAND) -P CMakeFiles/Oblivious.dir/cmake_clean.cmake
.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/clean

lib/Oblivious/CMakeFiles/Oblivious.dir/depend:
	cd /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/lib/Oblivious /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious /home/shiv/Research/cs294-proj/federated-k-means/covert-cpp/build/lib/Oblivious/CMakeFiles/Oblivious.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : lib/Oblivious/CMakeFiles/Oblivious.dir/depend
