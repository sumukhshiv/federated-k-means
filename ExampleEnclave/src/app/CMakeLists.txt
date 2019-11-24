set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++17")

set(CLIENT_SRC_FILES enclave_u.c app.cpp bank1.cpp bank2.cpp bank3.cpp enclave_attestation.cpp sgx_utils/sgx_utils.cpp attestation_utils/network_ra.cpp bank1.cpp attestation_utils/ias_ra.cpp attestation_utils/ecp.cpp)

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES "enclave_u.c; enclave_u.h")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted enclave.edl
        --search-path ../enclave/ # enclave.edl
        --search-path ${SGX_SDK}/include
        --search-path ${MBEDTLS_SGX_ROOT_DIR}/lib # mbedtls_sgx.edl
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(app ${CLIENT_SRC_FILES})

include_directories(
        ${SGXSDK_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/Oblivious
        ${CMAKE_CURRENT_SOURCE_DIR}/attestation_utils
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(app ${CMAKE_CURRENT_SOURCE_DIR}/libOblivious.so
        ${CMAKE_CURRENT_SOURCE_DIR}/../app/libsample_libcrypto.so
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB} -lsgx_ukey_exchange
        -Wl,-rpath -Wl,/usr/local/lib
        -Wl,-rpath -Wl,${SGX_LIBRARY_PATH}
        -lpthread)

add_dependencies(app enclave)
