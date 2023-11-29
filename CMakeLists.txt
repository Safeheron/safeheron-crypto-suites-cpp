cmake_minimum_required(VERSION 3.10)

project("SafeheronCryptoSuites" VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")

cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0077 NEW)
cmake_policy(SET CMP0079 NEW)

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
add_library(${CMAKE_PROJECT_NAME} SHARED "")

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        src
        ${PROTOBUF_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        /usr/local/include
        )

target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)
target_link_libraries(${CMAKE_PROJECT_NAME}
        ${PROTOBUF_LIBRARIES}
        OpenSSL::Crypto
        -ldl
        )

add_subdirectory(src)

option(ENABLE_STARK "Enable stark curve" OFF)
if (${ENABLE_STARK})
        add_definitions(-DENABLE_STARK)
endif()

option(ENABLE_TESTS "Enable tests" OFF)
if (${ENABLE_TESTS})
    enable_testing()
    include_directories(
            src/crypto-suites
            /usr/local/include
    )
    link_directories(/usr/local/lib)

    add_subdirectory(test/crypto-bip32)
    add_subdirectory(test/crypto-bip39)
    add_subdirectory(test/crypto-bn)
    add_subdirectory(test/crypto-commitment)
    add_subdirectory(test/crypto-curve)
    add_subdirectory(test/crypto-ecies)
    add_subdirectory(test/crypto-encode)
    add_subdirectory(test/crypto-hash)
    add_subdirectory(test/crypto-paillier)
    add_subdirectory(test/crypto-sss)
    add_subdirectory(test/crypto-zkp)
endif()

include("cmake/setup_installation.cmake")