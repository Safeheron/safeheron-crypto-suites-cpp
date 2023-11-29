find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        ${GTEST_INCLUDE_DIRS}
        ../../doc/crypto-ecies-cpp/src
        /usr/local/include  # This directory is included default on linux but not on Mac os
)

link_libraries(${CMAKE_PROJECT_NAME}
            ${PROTOBUF_LIBRARIES}
            ${GTEST_BOTH_LIBRARIES}
            pthread )


add_executable(auth-enc-test auth-enc-test.cpp)
add_test(NAME ecies.auth-enc-test COMMAND auth-enc-test)

add_executable(ecies-test ecies-test.cpp)
add_test(NAME ecies.ecies-test COMMAND ecies-test)

add_executable(curve-param-test curve-param-test.cpp)
add_test(NAME ecies.curve-param-test COMMAND curve-param-test)
