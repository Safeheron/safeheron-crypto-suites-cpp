cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoPaillier REQUIRED)

add_executable(example example.cpp)
target_include_directories(example PUBLIC
        ${CryptoPaillier_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        )

target_link_libraries(example PUBLIC
        CryptoPaillier
        OpenSSL::Crypto
        pthread )