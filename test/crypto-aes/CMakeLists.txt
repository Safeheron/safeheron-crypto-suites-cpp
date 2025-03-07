find_package(GTest REQUIRED)

include_directories(${GTEST_INCLUDE_DIRS})
include_directories("../../src/crypto-suites/crypto-aes")
include_directories(/usr/local/include)

link_libraries(${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread)

add_executable(aes-gcm-test aes-gcm-test.cpp)
add_test(NAME aes-gcm-test COMMAND aes-gcm-test)

add_executable(aes-gcm-identical-test aes-gcm-identical-test.cpp)
add_test(NAME aes-gcm-identical-test COMMAND aes-gcm-identical-test)