include (CheckCSourceRuns)
include (CheckCCompilerFlag)
include (CheckCXXCompilerFlag)

# Test for C++17 support
if (MSVC)
  check_cxx_compiler_flag ("/std:c++17" CXX_SUPPORTS_CXX17)
  set (CXX17_FLAG "/std:c++17")
else ()
  check_cxx_compiler_flag ("-std=c++17" CXX_SUPPORTS_CXX17)
  set (CXX17_FLAG "-std=c++17")
endif ()
if (NOT ${CXX_SUPPORTS_CXX17})
  message (WARNING "Your CXX compiler does not support C++17.")
endif ()

# Test for sufficient C++17 support for Covert C++
get_target_property (_COVERT_INCLUDE_DIRECTORIES Covert INTERFACE_INCLUDE_DIRECTORIES)
set (CMAKE_REQUIRED_FLAGS ${CXX17_FLAG})
set (CMAKE_REQUIRED_INCLUDES ${_COVERT_INCLUDE_DIRECTORIES})
check_cxx_source_compiles ("
#include \"SE.h\"
int main() {
  SE<int, H> arr[64] = {0};
  SE<int *, L, H> p = arr;
  p += 8;
  auto _p = se_static_cast<int *, H, H>(p);
}
"
  CXX_SUPPORTS_COVERT_CXX
)
unset (CMAKE_REQUIRED_FLAGS)
unset (CMAKE_REQUIRED_INCLUDES)
if (NOT ${CXX_SUPPORTS_COVERT_CXX})
  message (WARNING "Your compiler toolchain cannot compile Covert C++ code.\n")
endif ()

# Test for compiler AVX2 support
if (MSVC)
  check_c_compiler_flag ("/arch:AVX2" C_SUPPORTS_AVX2)
  set (AVX2_FLAG "/arch:AVX2")
else ()
  check_c_compiler_flag ("-mavx2" C_SUPPORTS_AVX2)
  set (AVX2_FLAG "-mavx2")
endif ()
if (NOT ${C_SUPPORTS_AVX2})
  message (WARNING
    "Your C compiler does not support AVX2.\n"
    "AVX2 support is required to compile the Covert C++ oblivious algorithms."
  )
endif ()

if (MSVC)
  check_cxx_compiler_flag ("/arch:AVX2" CXX_SUPPORTS_AVX2)
else ()
  check_cxx_compiler_flag ("-mavx2" CXX_SUPPORTS_AVX2)
endif ()
if (NOT ${CXX_SUPPORTS_AVX2})
  message (WARNING
    "Your CXX compiler does not support AVX2.\n"
    "AVX2 support is required to compile the Covert C++ oblivious algorithms."
  )
endif ()

# Test for platform AVX2 support
if (MSVC)
  set (OPT_FLAG "/Od")
else ()
  set (OPT_FLAG "-O0")
endif ()
set (CMAKE_REQUIRED_FLAGS ${AVX2_FLAG} ${OPT_FLAG})
check_c_source_runs ("
#include <immintrin.h>
int main(int argc, const char *argv[]) {
  int cond = argc == 1;
  __m256i dst, left = {0}, right = {0};
  const __m256i mask = _mm256_set1_epi32(!!cond - 1);
  const __m256i ltmp = _mm256_loadu_si256(&left);
  const __m256i rtmp = _mm256_loadu_si256(&right);
  const __m256i result = _mm256_blendv_epi8(ltmp, rtmp, mask);
  _mm256_storeu_si256(&dst, result);
}
"
  PLATFORM_SUPPORTS_AVX2
)
unset (CMAKE_REQUIRED_FLAGS)
if (NOT ${PLATFORM_SUPPORTS_AVX2})
  message (WARNING
    "Your platform architecture does not support AVX2.\n"
    "AVX2 support is required to run the Covert C++ oblivious algorithms."
  )
endif ()
