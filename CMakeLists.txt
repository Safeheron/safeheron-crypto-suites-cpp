cmake_minimum_required(VERSION 3.10)

# PLATFORM option behavior:
# - Not specified (-DPLATFORM not set): builds for the default (non-SGX) platform
# - Specified as -DPLATFORM=SGX      : enables SGX-specific build logic
# - Specified as any other value     : triggers an error (only SGX is supported as a special platform)
if (DEFINED PLATFORM AND NOT PLATFORM STREQUAL "SGX")
    message(FATAL_ERROR "Unsupported PLATFORM: ${PLATFORM}. Only 'SGX' is supported, or leave it unset for the default platform.")
endif()

# Check platform
if (PLATFORM STREQUAL "SGX")
    project("SafeheronCryptoSuitesSgx" VERSION 1.0.1)
else()
    project("SafeheronCryptoSuites" VERSION 1.0.1)
endif()

set(CMAKE_BUILD_TYPE "Release")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")

cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0077 NEW)
cmake_policy(SET CMP0079 NEW)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
if (PLATFORM STREQUAL "SGX")
    add_library(${CMAKE_PROJECT_NAME} STATIC "")
else()
    add_library(${CMAKE_PROJECT_NAME} "")
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED YES
        POSITION_INDEPENDENT_CODE ON
)

option(ENABLE_STARK "Enable stark curve" OFF)
if (${ENABLE_STARK})
    add_definitions(-DENABLE_STARK)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC ENABLE_STARK)
endif()

option(ENABLE_SNAP_SCOPE "Enable Snap Scope" OFF)
if (${ENABLE_SNAP_SCOPE})
    target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC ENABLE_SNAP_SCOPE)
    message(STATUS "Notice: ******************* Enable Snap Scope in Crypto-Suites ******************* ")
endif()

include_directories(src)

if (PLATFORM STREQUAL "SGX")
    add_definitions(-DPB_ENABLE_SGX)
    add_definitions(-DSAFEHERON_SGX_SDK)

    # Set the sgxsdk path
    set(SGX_SDK_PATH "/opt/intel/sgxsdk")
    set(SGX_SDK_INCLUDE_DIR "${SGX_SDK_PATH}/include")
    set(SGX_SDK_LIBRARIES_DIR "${SGX_SDK_PATH}/lib64")
    set(SGX_C_INCLUDE_DIR "${SGX_SDK_INCLUDE_DIR}/tlibc")
    set(SGX_CXX_INCLUDE_DIR "${SGX_SDK_INCLUDE_DIR}/libcxx")
    set(SGX_PROTOBUF_INCLUDE_DIR "${SGX_SDK_INCLUDE_DIR}/tprotobuf")

    # Set the sgxssl path
    set(SGX_SSL_PATH "/opt/intel/sgxssl")
    set(SGX_SSL_INCLUDE_DIR "${SGX_SSL_PATH}/include")
    set(SGX_SSL_LIBRARIES_DIR "${SGX_SSL_PATH}/lib64")
    set(TRUST_SGX_SSL_LIBRARY "${SGX_SSL_LIBRARIES_DIR}/libsgx_tsgxssl.a")
    set(TRUST_SGX_SSL_CRYPTO_LIBRARY "${SGX_SSL_LIBRARIES_DIR}/libsgx_tsgxssl_crypto.a")
    set(UNTRUST_SGX_SSL_LIBRARY "${SGX_SSL_LIBRARIES_DIR}/libsgx_usgxssl.a")

    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
            ${SGX_SSL_INCLUDE_DIR}
            ${SGX_SDK_INCLUDE_DIR}
            ${SGX_C_INCLUDE_DIR}
            ${SGX_CXX_INCLUDE_DIR}
            ${SGX_PROTOBUF_INCLUDE_DIR}
    )
else ()
    find_package(Protobuf REQUIRED)
    #set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)

    target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)
    target_link_libraries(${CMAKE_PROJECT_NAME}
            protobuf::libprotobuf
            OpenSSL::Crypto
    )

    option(ENABLE_TESTS "Enable tests" OFF)
    if (${ENABLE_TESTS})
        include(CTest)
        enable_testing()
        add_subdirectory(test)
    endif()
endif ()

add_subdirectory(src)

include("cmake/setup_installation.cmake")