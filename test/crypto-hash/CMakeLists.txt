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

add_executable(hmac-sha512-test hmac-sha512-test.cpp)
add_test(NAME hash.hmac-sha512-test COMMAND hmac-sha512-test)

add_executable(keccak256-test keccak256-test.cpp)
add_test(NAME hash.keccak256-test COMMAND keccak256-test)

add_executable(shake256-test shake256-test.cpp)
add_test(NAME hash.shake256-test COMMAND shake256-test)

add_executable(shake128-test shake128-test.cpp)
add_test(NAME hash.shake128-test COMMAND shake128-test)
