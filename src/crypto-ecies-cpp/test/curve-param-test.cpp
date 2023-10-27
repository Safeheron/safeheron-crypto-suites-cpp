#include "crypto-ecies/ecies.h"
#include "crypto-ecies/auth_enc.h"
#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include <crypto-bn/bn.h>
#include <crypto-bn/rand.h>
#include <crypto-curve/curve.h>
#include <crypto-encode/base64.h>
#include <crypto-encode/hex.h>

using namespace safeheron::bignum;
using namespace safeheron::curve;
using namespace safeheron::rand;
using namespace safeheron::encode;

using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::ecies::ECIES;
using safeheron::ecies::AuthEnc;

const std::vector<std::string> message_arr = {
        {0, 1, 2, 3, 4, 5},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33},
};

static void show_mem(const char * prefix, const char * buf, size_t len){
    if(prefix){
        printf("%s", prefix);
    }
    if(buf){
        std::string out;
        out=hex::EncodeToHex((const uint8_t *)(buf), len);
        printf("%s", out.c_str());
    }
    printf("\n");
}

void testCurveEncWithParams(const std::string &message,
                            CurveType c_type, 
                            safeheron::ecies::SYMM_ALG symm_alg,
                            safeheron::ecies::KDF_TYPE kdf_type,
                            safeheron::ecies::HMAC_ALG hmac_alg,
                            const std::string & derivation_iv,
                            const std::string & mac_iv)
{
    std::string plain;
    std::string cypher;
    std::string iv;
    const Curve *curv = GetCurveParam(c_type);

    printf("c_type: %d, symm_alg: %d, kdf_type: %d, hmac_alg: %d\n", (int)c_type, (int)symm_alg, (int)kdf_type, (int)hmac_alg);
    printf("derivation_iv: %s, mac_iv: %s\n", derivation_iv.c_str(), mac_iv.c_str());

    BN priv = RandomBNLt(curv->n);
    CurvePoint pub = curv->g * priv;

    bool ok = true;
    ECIES enc;

    // set ECIES parameters
    enc.set_curve_type(c_type);
    enc.set_symm_alg(symm_alg);
    enc.set_kdf_type(kdf_type);
    enc.set_mac_type(hmac_alg);
    enc.set_derivation_iv((const unsigned char*)derivation_iv.c_str(), derivation_iv.length());
    enc.set_mac_iv((const unsigned char*)mac_iv.c_str(), mac_iv.length());

    // do ECIES encrytion
    ok = enc.Encrypt(pub, message, iv, cypher);
    EXPECT_TRUE(ok);
    show_mem("cypher: ", cypher.c_str(), cypher.length());

    // do ECIES decrytion
    ok = enc.Decrypt(priv, cypher, iv, plain);
    EXPECT_TRUE(ok);
    show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < message.length(); i ++){
        EXPECT_EQ(message[i], plain[i]);
    }
}

TEST(Curve_ENC, ECIES_WithParams)
{
    const safeheron::ecies::SYMM_ALG symm_algs[] = {safeheron::ecies::SYMM_ALG::DESede_CBC,
                                              safeheron::ecies::SYMM_ALG::AES128_CBC,
                                              safeheron::ecies::SYMM_ALG::AES192_CBC,
                                              safeheron::ecies::SYMM_ALG::AES256_CBC
                                              };
    const safeheron::ecies::KDF_TYPE kdf_types[] = {safeheron::ecies::KDF_TYPE::KDF_X9_63_With_SHA1,
                                              safeheron::ecies::KDF_TYPE::KDF_X9_63_With_SHA256,
                                              safeheron::ecies::KDF_TYPE::KDF_X9_63_With_SHA384,
                                              safeheron::ecies::KDF_TYPE::KDF_X9_63_With_SHA512,
                                              safeheron::ecies::KDF_TYPE::KDF1_18033_With_SHA1,
                                              safeheron::ecies::KDF_TYPE::KDF1_18033_With_SHA256,
                                              safeheron::ecies::KDF_TYPE::KDF1_18033_With_SHA384,
                                              safeheron::ecies::KDF_TYPE::KDF1_18033_With_SHA512,
                                              safeheron::ecies::KDF_TYPE::KDF2_18033_With_SHA1,
                                              safeheron::ecies::KDF_TYPE::KDF2_18033_With_SHA256,
                                              safeheron::ecies::KDF_TYPE::KDF2_18033_With_SHA384,
                                              safeheron::ecies::KDF_TYPE::KDF2_18033_With_SHA512
                                              };
    const safeheron::ecies::HMAC_ALG hmac_algs[] = {safeheron::ecies::HMAC_ALG::HMAC_SHA1,
                                              safeheron::ecies::HMAC_ALG::HMAC_SHA256,
                                              safeheron::ecies::HMAC_ALG::HMAC_SHA384,
                                              safeheron::ecies::HMAC_ALG::HMAC_SHA512
                                              };
    const std::string derivation_iv[] = {"", "11111111"};
    const std::string mac_iv[] = {"", "11111111"};

    size_t symm_alg_cnt = sizeof(symm_algs)/sizeof(symm_algs[0]);
    size_t kdf_type_cnt = sizeof(kdf_types)/sizeof(kdf_types[0]);
    size_t hmac_alg_cnt = sizeof(hmac_algs)/sizeof(hmac_algs[0]);
    size_t derivation_iv_cnt = sizeof(derivation_iv)/sizeof(derivation_iv[0]);
    size_t mac_iv_cnt = sizeof(mac_iv)/sizeof(mac_iv[0]);

    for(size_t i = 0; i < message_arr.size(); i++) {
        for (size_t j = 0; j < symm_alg_cnt; j++) {
            for (size_t k = 0; k < kdf_type_cnt; k++) {
                for (size_t m = 0; m < hmac_alg_cnt; m++) {
                    for (size_t n = 0; n < derivation_iv_cnt; n++) {
                        for (size_t l = 0; l < mac_iv_cnt; l++ ) {
                            testCurveEncWithParams(message_arr[i], CurveType::P256, 
                                symm_algs[j], kdf_types[k], hmac_algs[m], derivation_iv[n], mac_iv[l]);
                        }
                    }
                }
            }
        }
    }
    for(size_t i = 0; i < message_arr.size(); i++) {
        for (size_t j = 0; j < symm_alg_cnt; j++) {
            for (size_t k = 0; k < kdf_type_cnt; k++) {
                for (size_t m = 0; m < hmac_alg_cnt; m++) {
                    for (size_t n = 0; n < derivation_iv_cnt; n++) {
                        for (size_t l = 0; l < mac_iv_cnt; l++ ) {
                            testCurveEncWithParams(message_arr[i], CurveType::SECP256K1, 
                                symm_algs[j], kdf_types[k], hmac_algs[m], derivation_iv[n], mac_iv[l]);
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
