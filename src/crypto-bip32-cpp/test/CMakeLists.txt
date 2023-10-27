find_package(GTest REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(${GTEST_INCLUDE_DIRS})
include_directories(../src)
include_directories(/usr/local/include)

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    link_directories(/usr/local/lib)
    link_libraries(CryptoBIP32
            ${GTEST_BOTH_LIBRARIES}
            pthread )
else()
    link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
endif()

# test cases for bip32-secp256k1
add_executable(bip32-secp256k1-serialization-test bip32-secp256k1-serialization-test.cpp)
add_test(NAME bip32-secp256k1-serialization-test COMMAND bip32-secp256k1-serialization-test)

add_executable(bip32-secp256k1-public-CKD-test bip32-secp256k1-public-CKD-test.cpp)
add_test(NAME bip32-secp256k1-public-CKD-test COMMAND bip32-secp256k1-public-CKD-test)

add_executable(bip32-secp256k1-private-CKD-test bip32-secp256k1-private-CKD-test.cpp)
add_test(NAME bip32-secp256k1-private-CKD-test COMMAND bip32-secp256k1-private-CKD-test)

add_executable(bip32-secp256k1-official-test bip32-secp256k1-official-test.cpp)
add_test(NAME bip32-secp256k1-official-test COMMAND bip32-secp256k1-official-test)

add_executable(bip32-secp256k1-CreateHDKey-test bip32-secp256k1-CreateHDKey-test.cpp)
add_test(NAME bip32-secp256k1-CreateHDKey-test COMMAND bip32-secp256k1-CreateHDKey-test)

# test cases for bip32-ed25519
add_executable(bip32-ed25519-serialization-test bip32-ed25519-serialization-test.cpp)
add_test(NAME bip32-ed25519-serialization-test COMMAND bip32-ed25519-serialization-test)

add_executable(bip32-ed25519-public-CKD-test bip32-ed25519-public-CKD-test.cpp)
add_test(NAME bip32-ed25519-public-CKD-test COMMAND bip32-ed25519-public-CKD-test)

add_executable(bip32-ed25519-private-CKD-test bip32-ed25519-private-CKD-test.cpp)
add_test(NAME bip32-ed25519-private-CKD-test COMMAND bip32-ed25519-private-CKD-test)

add_executable(bip32-ed25519-CreateHDKey-test bip32-ed25519-CreateHDKey-test.cpp)
add_test(NAME bip32-ed25519-CreateHDKey-test COMMAND bip32-ed25519-CreateHDKey-test)

add_executable(bip32-hd-path-test bip32-hd-path-test.cpp)
add_test(NAME bip32-hd-path-test COMMAND bip32-hd-path-test)

add_executable(bip32-ed25519-WithJs-test bip32-ed25519-WithJs-test.cpp)
add_test(NAME bip32-ed25519-WithJs-test COMMAND bip32-ed25519-WithJs-test)

add_executable(generate-data-test generate-data-test.cpp)
add_test(NAME generate-data-test COMMAND generate-data-test)

#add_executable(bip32-verification-test bip32-verification-test.cpp)
#add_test(NAME bip32-verification-test COMMAND bip32-verification-test)

add_executable(bip32-boundary-test bip32-boundary-test.cpp)
add_test(NAME bip32-boundary-test COMMAND bip32-boundary-test)

