find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories("../../src/crypto-suites/crypto-sss")

link_libraries(${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread )


add_executable(sss-test sss-test.cpp)
add_test(NAME sss.sss-test COMMAND sss-test)


