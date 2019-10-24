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
CMAKE_SOURCE_DIR = /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave

# Include any dependencies generated for this target.
include src/enclave/CMakeFiles/enclave.dir/depend.make

# Include the progress variables for this target.
include src/enclave/CMakeFiles/enclave.dir/progress.make

# Include the compile flags for this target's objects.
include src/enclave/CMakeFiles/enclave.dir/flags.make

src/enclave/enclave_t.c: src/enclave/enclave.edl
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating enclave_t.c"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /home/shiv/Research/Intel-SGX-Installation/linux-sgx/linux/installer/bin/sgxsdk/bin/x64/sgx_edger8r --trusted enclave.edl --search-path /home/shiv/Research/Intel-SGX-Installation/linux-sgx/linux/installer/bin/sgxsdk/include --search-path /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave

src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o: src/enclave/CMakeFiles/enclave.dir/flags.make
src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o: src/enclave/enclave.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/enclave.dir/enclave.cpp.o -c /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/enclave.cpp

src/enclave/CMakeFiles/enclave.dir/enclave.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/enclave.dir/enclave.cpp.i"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/enclave.cpp > CMakeFiles/enclave.dir/enclave.cpp.i

src/enclave/CMakeFiles/enclave.dir/enclave.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/enclave.dir/enclave.cpp.s"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/enclave.cpp -o CMakeFiles/enclave.dir/enclave.cpp.s

src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.requires:

.PHONY : src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.requires

src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.provides: src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.requires
	$(MAKE) -f src/enclave/CMakeFiles/enclave.dir/build.make src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.provides.build
.PHONY : src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.provides

src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.provides.build: src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o


src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o: src/enclave/CMakeFiles/enclave.dir/flags.make
src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o: src/enclave/enclave_t.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/enclave.dir/enclave_t.c.o   -c /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/enclave_t.c

src/enclave/CMakeFiles/enclave.dir/enclave_t.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/enclave.dir/enclave_t.c.i"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/enclave_t.c > CMakeFiles/enclave.dir/enclave_t.c.i

src/enclave/CMakeFiles/enclave.dir/enclave_t.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/enclave.dir/enclave_t.c.s"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/enclave_t.c -o CMakeFiles/enclave.dir/enclave_t.c.s

src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.requires:

.PHONY : src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.requires

src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.provides: src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.requires
	$(MAKE) -f src/enclave/CMakeFiles/enclave.dir/build.make src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.provides.build
.PHONY : src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.provides

src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.provides.build: src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o


src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o: src/enclave/CMakeFiles/enclave.dir/flags.make
src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o: src/enclave/sealing/sealing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/enclave.dir/sealing/sealing.cpp.o -c /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/sealing/sealing.cpp

src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/enclave.dir/sealing/sealing.cpp.i"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/sealing/sealing.cpp > CMakeFiles/enclave.dir/sealing/sealing.cpp.i

src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/enclave.dir/sealing/sealing.cpp.s"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/sealing/sealing.cpp -o CMakeFiles/enclave.dir/sealing/sealing.cpp.s

src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.requires:

.PHONY : src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.requires

src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.provides: src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.requires
	$(MAKE) -f src/enclave/CMakeFiles/enclave.dir/build.make src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.provides.build
.PHONY : src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.provides

src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.provides.build: src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o


# Object files for target enclave
enclave_OBJECTS = \
"CMakeFiles/enclave.dir/enclave.cpp.o" \
"CMakeFiles/enclave.dir/enclave_t.c.o" \
"CMakeFiles/enclave.dir/sealing/sealing.cpp.o"

# External object files for target enclave
enclave_EXTERNAL_OBJECTS =

enclave.so: src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o
enclave.so: src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o
enclave.so: src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o
enclave.so: src/enclave/CMakeFiles/enclave.dir/build.make
enclave.so: src/enclave/CMakeFiles/enclave.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX shared library ../../enclave.so"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/enclave.dir/link.txt --verbose=$(VERBOSE)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold "Signing the enclave => /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/enclave.signed.so"
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && /home/shiv/Research/Intel-SGX-Installation/linux-sgx/linux/installer/bin/sgxsdk/bin/x64/sgx_sign sign -key enclave_private.pem -config enclave.config.xml -enclave /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/enclave.so -out /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/enclave.signed.so

# Rule to build all files generated by this target.
src/enclave/CMakeFiles/enclave.dir/build: enclave.so

.PHONY : src/enclave/CMakeFiles/enclave.dir/build

src/enclave/CMakeFiles/enclave.dir/requires: src/enclave/CMakeFiles/enclave.dir/enclave.cpp.o.requires
src/enclave/CMakeFiles/enclave.dir/requires: src/enclave/CMakeFiles/enclave.dir/enclave_t.c.o.requires
src/enclave/CMakeFiles/enclave.dir/requires: src/enclave/CMakeFiles/enclave.dir/sealing/sealing.cpp.o.requires

.PHONY : src/enclave/CMakeFiles/enclave.dir/requires

src/enclave/CMakeFiles/enclave.dir/clean:
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave && $(CMAKE_COMMAND) -P CMakeFiles/enclave.dir/cmake_clean.cmake
.PHONY : src/enclave/CMakeFiles/enclave.dir/clean

src/enclave/CMakeFiles/enclave.dir/depend: src/enclave/enclave_t.c
	cd /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave /home/shiv/Research/cs294-proj/federated-k-means/ExampleEnclave/src/enclave/CMakeFiles/enclave.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/enclave/CMakeFiles/enclave.dir/depend

