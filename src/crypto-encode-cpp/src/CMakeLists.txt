target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-encode/hex_imp.c
        crypto-encode/hex.cpp
        crypto-encode/base64_imp.cpp
        crypto-encode/base64.cpp
        crypto-encode/base58.cpp
        crypto-encode/base58_imp.cpp
        )


# Refer to single internal library only if it's not assembled into a big library.
option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    find_package(CryptoHash REQUIRED)

    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CryptoHash_INCLUDE_DIRS})

    target_link_libraries(${CMAKE_PROJECT_NAME} CryptoHash)
endif()
