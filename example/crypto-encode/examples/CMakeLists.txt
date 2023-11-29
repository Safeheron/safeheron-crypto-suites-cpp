cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(CryptoEncode REQUIRED)

add_executable(example example.cpp)
target_include_directories(example PUBLIC
        ${CryptoEncode_INCLUDE_DIRS}
        /usr/local/include  # This directory is included default on linux but not on Mac os
        )

# This directory is included default on linux but not on Mac os
target_link_directories(example PUBLIC /usr/local/lib)

target_link_libraries(example PUBLIC
        CryptoEncode
        pthread )