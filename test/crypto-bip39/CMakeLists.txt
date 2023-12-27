find_package(GTest REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(${GTEST_INCLUDE_DIRS})
include_directories("../../src/crypto-suites/crypto-bip39")
include_directories(/usr/local/include)

link_libraries(${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread )

add_executable(bip39-test bip39-test.cpp)
add_test(NAME bip39.bip39-test COMMAND bip39-test)

add_executable(bip39-internal-test bip39-internal-test.cpp)
add_test(NAME bip39.bip39-internal-test COMMAND bip39-internal-test)

add_executable(bip39-16bytes-test bip39-16bytes-test.cpp)
add_test(NAME bip39.bip39-16bytes-test COMMAND bip39-16bytes-test)

add_executable(bip39-20bytes-test bip39-20bytes-test.cpp)
add_test(NAME bip39.bip39-20bytes-test COMMAND bip39-20bytes-test)

add_executable(bip39-24bytes-test bip39-24bytes-test.cpp)
add_test(NAME bip39.bip39-24bytes-test COMMAND bip39-24bytes-test)

add_executable(bip39-28bytes-test bip39-28bytes-test.cpp)
add_test(NAME bip39.bip39-28bytes-test COMMAND bip39-28bytes-test)

add_executable(bip39-32bytes-test bip39-32bytes-test.cpp)
add_test(NAME bip39.bip39-32bytes-test COMMAND bip39-32bytes-test)

add_executable(bip39-official-test bip39-official-test.cpp)
add_test(NAME bip39.bip39-official-test COMMAND bip39-official-test)