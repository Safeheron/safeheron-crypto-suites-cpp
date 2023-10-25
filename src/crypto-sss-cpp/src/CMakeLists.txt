target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-sss/polynomial.cpp
        crypto-sss/vsss.cpp
        crypto-sss/vsss_ed25519.cpp
        crypto-sss/vsss_secp256k1.cpp
        )

# Refer to single internal library only if it's not assembled into a big library.
option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    find_package(PkgConfig REQUIRED)
    pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

    #set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)

    find_package(CryptoBN REQUIRED)
    find_package(CryptoEncode REQUIRED)
    find_package(CryptoCurve REQUIRED)

    target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
            ${CryptoEncode_INCLUDE_DIRS}
            ${CryptoBN_INCLUDE_DIRS}
            ${CryptoCurve_INCLUDE_DIRS}
            ${PROTOBUF_INCLUDE_DIRS}
            /usr/local/include
            )

    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
            ${OPENSSL_INCLUDE_DIR}
            )

    target_link_directories(${CMAKE_PROJECT_NAME} PUBLIC /usr/local/lib)
    target_link_libraries(${CMAKE_PROJECT_NAME}
            ${PROTOBUF_LIBRARIES}
            OpenSSL::Crypto
            -ldl
            CryptoBN
            CryptoEncode
            CryptoCurve
            )
endif()
