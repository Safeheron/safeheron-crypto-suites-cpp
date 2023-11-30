file(GLOB SOURCE_crypto-bip32
        crypto-suites/crypto-bip32/bip32.cpp
        crypto-suites/crypto-bip32/bip32_ecdsa.cpp
        crypto-suites/crypto-bip32/bip32_ed25519.cpp
        crypto-suites/crypto-bip32/hd_path.cpp
        crypto-suites/crypto-bip32/memzero.c
        )

file(GLOB SOURCE_crypto-bip39
        crypto-suites/crypto-bip39/wordlist.c
        crypto-suites/crypto-bip39/wally_mnemonic.c
        crypto-suites/crypto-bip39/wally_bip39.c
        crypto-suites/crypto-bip39/internal.c
        crypto-suites/crypto-bip39/hash_wrapper.cpp
        crypto-suites/crypto-bip39/memzero.c
        crypto-suites/crypto-bip39/bip39.cpp
        )

file(GLOB SOURCE_crypto-bn
        crypto-suites/crypto-bn/bn.cpp
        crypto-suites/crypto-bn/rand.cpp
        )

file(GLOB SOURCE_crypto-commitment
        crypto-suites/crypto-commitment/commitment.cpp
        crypto-suites/crypto-commitment/com256.cpp
        crypto-suites/crypto-commitment/com512.cpp
        crypto-suites/crypto-commitment/kgd_curve_point.cpp
        crypto-suites/crypto-commitment/kgd_number.cpp
        crypto-suites/crypto-commitment/proto_gen/commitment.pb.switch.cc
        )

file(GLOB ed25519-donna_SOURCES
        third_party/ed25519-donna/curve25519-donna-32bit.c
        third_party/ed25519-donna/curve25519-donna-helpers.c
        third_party/ed25519-donna/curve25519-donna-scalarmult-base.c
        third_party/ed25519-donna/ed25519.c
        third_party/ed25519-donna/ed25519-donna-32bit-tables.c
        third_party/ed25519-donna/ed25519-donna-basepoint-table.c
        third_party/ed25519-donna/ed25519-donna-impl-base.c
        third_party/ed25519-donna/ed25519-donna-memzero.c
        #        third_party/ed25519-donna/ed25519-sha3.c
        #        third_party/ed25519-donna/ed25519-keccak.c
        third_party/ed25519-donna/modm-donna-32bit.c
        )

file(GLOB SOURCE_crypto-curve
        crypto-suites/crypto-curve/ed25519_ex.c
        crypto-suites/crypto-curve/curve.cpp
        crypto-suites/crypto-curve/curve_point.cpp
        crypto-suites/crypto-curve/proto_gen/curve_point.pb.switch.cc
        crypto-suites/crypto-curve/openssl_curve_wrapper.cpp
        crypto-suites/crypto-curve/ecdsa.cpp
        crypto-suites/crypto-curve/eddsa.cpp
        ${ed25519-donna_SOURCES}
        )

file(GLOB SOURCE_crypto-ecies
        crypto-suites/crypto-ecies/auth_enc.cpp
        crypto-suites/crypto-ecies/ecies.cpp
        crypto-suites/crypto-ecies/hmac.cpp
        crypto-suites/crypto-ecies/kdf.cpp
        crypto-suites/crypto-ecies/symm.cpp
        )

file(GLOB SOURCE_crypto-encode
        crypto-suites/crypto-encode/hex_imp.c
        crypto-suites/crypto-encode/hex.cpp
        crypto-suites/crypto-encode/base64_imp.cpp
        crypto-suites/crypto-encode/base64.cpp
        crypto-suites/crypto-encode/base58.cpp
        crypto-suites/crypto-encode/base58_imp.cpp
        )

file(GLOB SOURCE_crypto-hash
        crypto-suites/crypto-hash/sha1.cpp
        crypto-suites/crypto-hash/sha256.cpp
        crypto-suites/crypto-hash/sha512.cpp
        crypto-suites/crypto-hash/hash160.cpp
        crypto-suites/crypto-hash/hash256.cpp
        crypto-suites/crypto-hash/ripemd160.cpp
        crypto-suites/crypto-hash/chacha20.cpp
        crypto-suites/crypto-hash/hmac_sha256.cpp
        crypto-suites/crypto-hash/hmac_sha512.cpp
        crypto-suites/crypto-hash/safe_hash256.cpp
        crypto-suites/crypto-hash/safe_hash512.cpp
        )

file(GLOB SOURCE_crypto-paillier
        crypto-suites/crypto-paillier/pail.cpp
        crypto-suites/crypto-paillier/pail_privkey.cpp
        crypto-suites/crypto-paillier/pail_pubkey.cpp
        crypto-suites/crypto-paillier/proto_gen/paillier.pb.switch.cc
        )

file(GLOB SOURCE_crypto-sss
        crypto-suites/crypto-sss/polynomial.cpp
        crypto-suites/crypto-sss/vsss.cpp
        crypto-suites/crypto-sss/vsss_ed25519.cpp
        crypto-suites/crypto-sss/vsss_secp256k1.cpp
        )

if (${ENABLE_SNAP_SCOPE})
    file(GLOB SOURCE_crypto-zkp
            crypto-suites/crypto-zkp/proto_gen/zkp.pb.switch.cc
            crypto-suites/crypto-zkp/dln_proof.cpp
            crypto-suites/crypto-zkp/dlog_proof.cpp
            crypto-suites/crypto-zkp/dlog_proof_v2.cpp
            crypto-suites/crypto-zkp/dlog_proof_v3.cpp
#            crypto-suites/crypto-zkp/heg_proof.cpp
#            crypto-suites/crypto-zkp/heg_proof_v2.cpp
#            crypto-suites/crypto-zkp/heg_proof_v3.cpp
#            crypto-suites/crypto-zkp/linear_combination_proof.cpp
            crypto-suites/crypto-zkp/no_small_factor_proof.cpp
#            crypto-suites/crypto-zkp/pail_proof.cpp
#            crypto-suites/crypto-zkp/range_proof.cpp
#            crypto-suites/crypto-zkp/pedersen_proof.cpp
            crypto-suites/crypto-zkp/dlog_elgamal_com_proof.cpp
            crypto-suites/crypto-zkp/dlog_equality_proof.cpp
#            crypto-suites/crypto-zkp/pdl_proof.cpp
#            crypto-suites/crypto-zkp/pail/pail_n_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_aff_range_proof.cpp
#            crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v1.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v2.cpp
#            crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v3.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_group_ele_range_proof.cpp
#            crypto-suites/crypto-zkp/pail/pail_aff_group_ele_range_proof_v1.cpp
            crypto-suites/crypto-zkp/pail/pail_aff_group_ele_range_proof_v2.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_elgamal_com_range_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_blum_modulus_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_dec_modulo_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_mul_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_mul_group_ele_range_proof.cpp
            crypto-suites/crypto-zkp/ring_pedersen_param_pub.cpp
            crypto-suites/crypto-zkp/ring_pedersen_param_priv.cpp
            crypto-suites/crypto-zkp/two_dln_proof.cpp
            )

    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
            ${SOURCE_crypto-bip39}
            ${SOURCE_crypto-bn}
            ${SOURCE_crypto-curve}
            ${SOURCE_crypto-ecies}
            ${SOURCE_crypto-encode}
            ${SOURCE_crypto-hash}
            ${SOURCE_crypto-paillier}
            ${SOURCE_crypto-sss}
            ${SOURCE_crypto-zkp}
            )
else()
    file(GLOB SOURCE_crypto-zkp
            crypto-suites/crypto-zkp/proto_gen/zkp.pb.switch.cc
            crypto-suites/crypto-zkp/dln_proof.cpp
            crypto-suites/crypto-zkp/dlog_proof.cpp
            crypto-suites/crypto-zkp/dlog_proof_v2.cpp
            crypto-suites/crypto-zkp/dlog_proof_v3.cpp
            crypto-suites/crypto-zkp/heg_proof.cpp
            crypto-suites/crypto-zkp/heg_proof_v2.cpp
            crypto-suites/crypto-zkp/heg_proof_v3.cpp
            crypto-suites/crypto-zkp/linear_combination_proof.cpp
            crypto-suites/crypto-zkp/no_small_factor_proof.cpp
            crypto-suites/crypto-zkp/pail_proof.cpp
            crypto-suites/crypto-zkp/range_proof.cpp
            crypto-suites/crypto-zkp/pedersen_proof.cpp
            crypto-suites/crypto-zkp/dlog_elgamal_com_proof.cpp
            crypto-suites/crypto-zkp/dlog_equality_proof.cpp
            crypto-suites/crypto-zkp/pdl_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_n_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_aff_range_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v1.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v2.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v3.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_group_ele_range_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_aff_group_ele_range_proof_v1.cpp
            crypto-suites/crypto-zkp/pail/pail_aff_group_ele_range_proof_v2.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_elgamal_com_range_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_blum_modulus_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_dec_modulo_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_enc_mul_proof.cpp
            crypto-suites/crypto-zkp/pail/pail_mul_group_ele_range_proof.cpp
            crypto-suites/crypto-zkp/ring_pedersen_param_pub.cpp
            crypto-suites/crypto-zkp/ring_pedersen_param_priv.cpp
            crypto-suites/crypto-zkp/two_dln_proof.cpp
            )

    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
            ${SOURCE_crypto-bip39}
            ${SOURCE_crypto-bn}
            ${SOURCE_crypto-curve}
            ${SOURCE_crypto-ecies}
            ${SOURCE_crypto-encode}
            ${SOURCE_crypto-hash}
            ${SOURCE_crypto-paillier}
            ${SOURCE_crypto-sss}
            ${SOURCE_crypto-zkp}
            ${SOURCE_crypto-bip32}
            ${SOURCE_crypto-commitment}
            )
endif()


target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE third_party)

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

