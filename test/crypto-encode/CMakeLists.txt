find_package(GTest REQUIRED)

include_directories(${GTEST_INCLUDE_DIRS})
include_directories("../../src/crypto-suites/crypto-encode")

link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )

add_executable(base64-test base64-test.cpp)
add_test(NAME encode.base64-test COMMAND base64-test)

add_executable(hex-test hex-test.cpp)
add_test(NAME encode.hex-test COMMAND hex-test)

add_executable(base58-test base58-test.cpp)
add_test(NAME encode.base58-test COMMAND base58-test)
