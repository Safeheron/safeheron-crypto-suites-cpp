find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories("../../src/crypto-suites/crypto-commitment")
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(/usr/local/include)

link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )

add_executable(commitment-test commitment-test.cpp)
add_test(NAME commitment.commitment-test COMMAND commitment-test)


