cmake_minimum_required(VERSION 3.10)
project(example)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(GTest REQUIRED)
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)
find_package(CryptoSSS REQUIRED)

add_executable(${PROJECT_NAME} example.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoSSS_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        /usr/local/include  # This directory is included default on linux but not on Mac os
)

# This directory is included default on linux but not on Mac os
target_link_directories(${PROJECT_NAME} PUBLIC /usr/local/lib)

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoSSS
        OpenSSL::Crypto
        pthread )