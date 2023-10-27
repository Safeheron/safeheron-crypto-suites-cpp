target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-zkp/proto_gen/zkp.pb.switch.cc
        crypto-zkp/dln_proof.cpp
        crypto-zkp/dlog_proof.cpp
        crypto-zkp/dlog_proof_v2.cpp
        crypto-zkp/dlog_proof_v3.cpp
        crypto-zkp/heg_proof.cpp
        crypto-zkp/heg_proof_v2.cpp
        crypto-zkp/linear_combination_proof.cpp
        crypto-zkp/heg_proof_v3.cpp
        crypto-zkp/no_small_factor_proof.cpp
        crypto-zkp/pail_proof.cpp
        crypto-zkp/range_proof.cpp
        crypto-zkp/pedersen_proof.cpp
        crypto-zkp/dlog_elgamal_com_proof.cpp
        crypto-zkp/dlog_equality_proof.cpp
        crypto-zkp/pdl_proof.cpp
        crypto-zkp/pail/pail_n_proof.cpp
        crypto-zkp/pail/pail_enc_range_proof_v3.cpp
        crypto-zkp/pail/pail_aff_range_proof.cpp
        crypto-zkp/pail/pail_enc_range_proof_v1.cpp
        crypto-zkp/pail/pail_enc_range_proof_v2.cpp
        crypto-zkp/pail/pail_enc_group_ele_range_proof.cpp
        crypto-zkp/pail/pail_aff_group_ele_range_proof_v1.cpp
        crypto-zkp/pail/pail_aff_group_ele_range_proof_v2.cpp
        crypto-zkp/pail/pail_enc_elgamal_com_range_proof.cpp
        crypto-zkp/pail/pail_blum_modulus_proof.cpp
        crypto-zkp/pail/pail_dec_modulo_proof.cpp
        crypto-zkp/pail/pail_enc_mul_proof.cpp
        crypto-zkp/pail/pail_mul_group_ele_range_proof.cpp
        crypto-zkp/ring_pedersen_param_pub.cpp
        crypto-zkp/ring_pedersen_param_priv.cpp
        crypto-zkp/two_dln_proof.cpp
        )

# Refer to single internal library only if it's not assembled into a big library.
option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    find_package(PkgConfig REQUIRED)
    pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

    #set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)

    find_package(CryptoBN REQUIRED)
    find_package(CryptoCommitment REQUIRED)
    find_package(CryptoEncode REQUIRED)
    find_package(CryptoCurve REQUIRED)
    find_package(CryptoHash REQUIRED)
    find_package(CryptoPaillier REQUIRED)

    target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
            ${PROTOBUF_INCLUDE_DIRS}
            ${CryptoBN_INCLUDE_DIRS}
            ${CryptoCommitment_INCLUDE_DIRS}
            ${CryptoEncode_INCLUDE_DIRS}
            ${CryptoHash_INCLUDE_DIRS}
            ${CryptoCurve_INCLUDE_DIRS}
            ${CryptoPaillier_INCLUDE_DIRS}
            )

    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
            ${OPENSSL_INCLUDE_DIR}
            )

    target_link_libraries(${CMAKE_PROJECT_NAME}
            ${PROTOBUF_LIBRARIES}
            OpenSSL::Crypto
            -ldl
            CryptoBN
            CryptoCommitment
            CryptoEncode
            CryptoCurve
            CryptoHash
            CryptoPaillier
            )
endif()
