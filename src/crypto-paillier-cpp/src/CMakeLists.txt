target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-paillier/pail.cpp
        crypto-paillier/pail_privkey.cpp
        crypto-paillier/pail_pubkey.cpp
        crypto-paillier/proto_gen/paillier.pb.switch.cc
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

    target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
            ${PROTOBUF_INCLUDE_DIRS}
            /usr/local/include  # This directory is included default on linux but not on Mac os
            ${CryptoEncode_INCLUDE_DIRS}
            ${CryptoBN_INCLUDE_DIRS}
            )

    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
            ${OPENSSL_INCLUDE_DIR}
            )


    # This directory is included default on linux but not on Mac os
    target_link_directories(${PROJECT_NAME} PUBLIC /usr/local/lib)
    target_link_libraries(${CMAKE_PROJECT_NAME}
            ${PROTOBUF_LIBRARIES}
            OpenSSL::Crypto
            -ldl
            CryptoBN
            CryptoEncode
            )
endif()
