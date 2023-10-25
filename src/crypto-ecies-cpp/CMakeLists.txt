cmake_minimum_required(VERSION 3.10)

project("CryptoECIES" VERSION 1.0.1)
set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Debug")
#SET(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0079 NEW)
add_library(${CMAKE_PROJECT_NAME} SHARED "")

add_subdirectory(src)

option(ENABLE_TESTS "Enable tests" OFF)
if (${ENABLE_TESTS})
    enable_testing()
    add_subdirectory(test)
endif()

include("cmake/setup_installation.cmake")
