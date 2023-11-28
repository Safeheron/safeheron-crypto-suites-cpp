find_package(GTest REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(${GTEST_INCLUDE_DIRS})
include_directories(../src)
include_directories(/usr/local/include)

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    #set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)

    find_package(CryptoBN REQUIRED)
    find_package(CryptoEncode REQUIRED)

    include_directories(
            ${OPENSSL_INCLUDE_DIR}
            ${CryptoBN_INCLUDE_DIRS}
            ${CryptoEncode_INCLUDE_DIRS}
            ${CryptoBIP39_INCLUDE_DIRS}
            )

    link_directories(/usr/local/lib)
    link_libraries(
            CryptoBN
            CryptoEncode
            CryptoBIP39
            ${GTEST_BOTH_LIBRARIES}
            pthread )
else()
    link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
endif()

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