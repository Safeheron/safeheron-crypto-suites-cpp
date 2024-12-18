cmake_minimum_required(VERSION 3.10)

project("SafeheronCryptoSuitesSgx" VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")

# Set all flags
set(SGX_COMMON_C_FLAGS "-m64 -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -nostdinc -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -nostdinc++ -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")

cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0077 NEW)
cmake_policy(SET CMP0079 NEW)

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

# Build libSafeheronCryptoSuitesSgx.a
add_library(${CMAKE_PROJECT_NAME} STATIC "")

# Set the source file path
set(CRYPTO_SUITES_SOURCE_PATH ${CMAKE_SOURCE_DIR}/src)
message(STATUS "CRYPTO_SUITES_SOURCE_PATH=${CRYPTO_SUITES_SOURCE_PATH}")

add_subdirectory(${CRYPTO_SUITES_SOURCE_PATH})

#include_directories(src)

option(ENABLE_SNAP_SCOPE "Enable Snap Scope" OFF)
if (${ENABLE_SNAP_SCOPE})
    message(STATUS "Notice: ******************* Enable Snap Scope in Crypto-Suites ******************* ")
endif()

# Additional include paths
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
		${CRYPTO_SUITES_SOURCE_PATH}
		${SGX_SSL_INCLUDE_DIR}
		${SGX_SDK_INCLUDE_DIR}
		${SGX_C_INCLUDE_DIR}
		${SGX_CXX_INCLUDE_DIR}
		${SGX_PROTOBUF_INCLUDE_DIR}
		)

include("cmake/setup_installation.cmake")