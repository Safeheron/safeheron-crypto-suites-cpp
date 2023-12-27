find_package(GTest REQUIRED)

include_directories("../../src/crypto-suites/crypto-hash"
        ${GTEST_INCLUDE_DIRS})

link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )

add_executable(hash-test hash-test.cpp)
add_test(NAME hash.hash-test COMMAND hash-test)

add_executable(sha256-test sha256-test.cpp)
add_test(NAME hash.sha256-test COMMAND sha256-test)

add_executable(sha512-test sha512-test.cpp)
add_test(NAME hash.sha512-test COMMAND sha512-test)

add_executable(safe-hash256-test safe-hash256-test.cpp)
add_test(NAME hash.safe-hash256-test COMMAND safe-hash256-test)

add_executable(safe-hash512-test safe-hash512-test.cpp)
add_test(NAME hash.safe-hash512-test COMMAND safe-hash512-test)