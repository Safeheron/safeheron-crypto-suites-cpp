target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-bip39/wordlist.c
        crypto-bip39/wally_mnemonic.c
        crypto-bip39/wally_bip39.c
        crypto-bip39/internal.c
        crypto-bip39/hash_wrapper.cpp
        crypto-bip39/memzero.c
        crypto-bip39/bip39.cpp
        )

# Refer to single internal library only if it's not assembled into a big library.
option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    find_package(CryptoHash REQUIRED)

    target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
            ${CryptoHash_INCLUDE_DIRS}
            /usr/local/include
            )

    target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)
    target_link_libraries(${CMAKE_PROJECT_NAME}
            CryptoHash
            )
endif()