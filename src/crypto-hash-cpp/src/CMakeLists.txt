target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-hash/sha1.cpp
        crypto-hash/sha256.cpp
        crypto-hash/sha512.cpp
        crypto-hash/hash160.cpp
        crypto-hash/hash256.cpp
        crypto-hash/ripemd160.cpp
        crypto-hash/chacha20.cpp
        crypto-hash/hmac_sha256.cpp
        crypto-hash/hmac_sha512.cpp
        crypto-hash/safe_hash256.cpp
        crypto-hash/safe_hash512.cpp
        )

# Check if file endian.h, byteswap.h, sys/endian.h exist.
include(CheckIncludeFileCXX)
CHECK_INCLUDE_FILE_CXX("endian.h" HAVE_ENDIAN_H)
CHECK_INCLUDE_FILE_CXX("byteswap.h" HAVE_BYTESWAP_H)
CHECK_INCLUDE_FILE_CXX("sys/endian.h" HAVE_SYS_ENDIAN_H)

if(HAVE_ENDIAN_H EQUAL 1)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE HAVE_ENDIAN_H)
endif()

if(HAVE_BYTESWAP_H EQUAL 1)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE HAVE_BYTESWAP_H)
endif()

if(HAVE_SYS_ENDIAN_H EQUAL 1)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE HAVE_SYS_ENDIAN_H)
endif()
# End check


