find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        "../src"
        ${PROTOBUF_INCLUDE_DIRS})

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    link_libraries(CryptoZKP
            ${GTEST_BOTH_LIBRARIES}
            pthread )
else()
    link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
endif()

add_executable(dln_proof_test dln_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.dln_proof_test COMMAND dln_proof_test)

add_executable(two_dln_proof_test two_dln_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.two_dln_proof_test COMMAND two_dln_proof_test)

add_executable(dlog_proof_test dlog_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.dlog_proof_test COMMAND dlog_proof_test)

add_executable(dlog_proof_v2_test dlog_proof_v2_test.cpp CTimer.cpp)
add_test(NAME zkp.dlog_proof_v2_test COMMAND dlog_proof_v2_test)

add_executable(dlog_proof_v3_test dlog_proof_v3_test.cpp CTimer.cpp)
add_test(NAME zkp.dlog_proof_v3_test COMMAND dlog_proof_v3_test)

add_executable(heg_proof_test heg_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.heg_proof_test COMMAND heg_proof_test)

add_executable(heg_proof_v2_test heg_proof_v2_test.cpp CTimer.cpp)
add_test(NAME zkp.heg_proof_v2_test COMMAND heg_proof_v2_test)

add_executable(linear_combination_proof_test linear_combination_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.linear_combination_proof_test COMMAND linear_combination_proof_test)

add_executable(heg_proof_v3_test heg_proof_v3_test.cpp CTimer.cpp)
add_test(NAME zkp.heg_proof_v3_test COMMAND heg_proof_v3_test)

add_executable(no_small_factor_proof_test no_small_factor_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.no_small_factor_proof_test COMMAND no_small_factor_proof_test)

add_executable(pail_N_test pail_N_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_N_test COMMAND pail_N_test)

add_executable(pail_test pail_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_test COMMAND pail_test)

add_executable(pedersen_proof_test pedersen_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pedersen_proof_test COMMAND pedersen_proof_test)

add_executable(range_proof_test range_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.range_proof_test COMMAND range_proof_test)

add_executable(pdl_proof_test pdl_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pdl_proof_test COMMAND pdl_proof_test)

add_executable(pail_enc_range_proof_v3_test pail_enc_range_proof_v3_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_enc_range_proof_v3_test COMMAND pail_enc_range_proof_v3_test)

add_executable(pail_enc_range_proof_v1_test pail_enc_range_proof_v1_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_enc_range_proof_v1_test COMMAND pail_enc_range_proof_v1_test)

add_executable(pail_enc_range_proof_v2_test pail_enc_range_proof_v2_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_enc_range_proof_v2_test COMMAND pail_enc_range_proof_v2_test)

add_executable(pail_enc_group_ele_range_proof_test pail_enc_group_ele_range_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_enc_group_ele_range_proof_test COMMAND pail_enc_group_ele_range_proof_test)

add_executable(pail_aff_range_proof_test pail_aff_range_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_aff_range_proof_test COMMAND pail_aff_range_proof_test)

add_executable(pail_aff_group_ele_range_proof_v1_test pail_aff_group_ele_range_proof_v1_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_aff_group_ele_range_proof_v1_test COMMAND pail_aff_group_ele_range_proof_v1_test)

add_executable(pail_aff_group_ele_range_proof_v2_test pail_aff_group_ele_range_proof_v2_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_aff_group_ele_range_proof_v2_test COMMAND pail_aff_group_ele_range_proof_v2_test)

add_executable(pail_enc_elgamal_com_range_proof_test pail_enc_elgamal_com_range_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_enc_elgamal_com_range_proof_test COMMAND pail_enc_elgamal_com_range_proof_test)

add_executable(dlog_elgamal_com_proof_test dlog_elgamal_com_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.dlog_elgamal_com_proof_test COMMAND dlog_elgamal_com_proof_test)

add_executable(dlog_equality_proof_test dlog_equality_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.dlog_equality_proof_test COMMAND dlog_equality_proof_test)

add_executable(pail_blum_modulus_proof_test pail_blum_modulus_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_blum_modulus_proof_test COMMAND pail_blum_modulus_proof_test)

add_executable(pail_mul_group_ele_range_proof_test pail_mul_group_ele_range_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_mul_group_ele_range_proof_test COMMAND pail_mul_group_ele_range_proof_test)

add_executable(pail_enc_mul_proof_test pail_enc_mul_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_enc_mul_proof_test COMMAND pail_enc_mul_proof_test)

add_executable(pail_dec_modulo_proof_test pail_dec_modulo_proof_test.cpp CTimer.cpp)
add_test(NAME zkp.pail_dec_modulo_proof_test COMMAND pail_dec_modulo_proof_test)
