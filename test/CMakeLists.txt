set(CMAKE_CXX_STANDARD 17)

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)

if (NOT ${ENABLE_SNAP_SCOPE})
    add_subdirectory(crypto-bip32)
    add_subdirectory(crypto-commitment)
endif()
add_subdirectory(crypto-bip39)
add_subdirectory(crypto-bn)
add_subdirectory(crypto-curve)
add_subdirectory(crypto-ecies)
add_subdirectory(crypto-encode)
add_subdirectory(crypto-hash)
add_subdirectory(crypto-paillier)
add_subdirectory(crypto-sss)
add_subdirectory(crypto-zkp)
add_subdirectory(crypto-aes)
