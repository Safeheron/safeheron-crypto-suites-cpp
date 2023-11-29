cmake_minimum_required(VERSION 3.10)
project(example)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(CryptoHash REQUIRED)

add_executable(example example.cpp)
target_include_directories(example PRIVATE
        ${CryptoHash_INCLUDE_DIRS}
        )

target_link_libraries(example PRIVATE
        CryptoHash
        pthread )