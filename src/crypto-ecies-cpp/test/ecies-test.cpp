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

void testECIES_0(const std::string &message, CurveType c_type){
    const Curve *curv = GetCurveParam(c_type);

    std::string plain;
    std::string cypher;
    std::string iv;

    //BN priv_a = BN::FromDecStr("4050298667054381376040649773970530311598264897556821662677634075002761777");
    //BN priv_b = BN::FromDecStr("2294226772740614508941417891614236736606752960073669253551166842586609531");
    BN priv = RandomBNLt(curv->n);
    CurvePoint pub = curv->g * priv;

    bool ok = true;
    ECIES enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(pub, (const uint8_t*)message.c_str(), message.length(), iv, cypher);
    EXPECT_TRUE(ok);
    show_mem("cypher: ", cypher.c_str(), cypher.length());
    ok = enc.Decrypt(priv, (const uint8_t*)cypher.c_str(), cypher.length(), (const uint8_t*)iv.c_str(), iv.length(), plain);
    EXPECT_TRUE(ok);
    show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < plain.length(); i ++){
        EXPECT_EQ(message[i], plain[i]);
    }
}

void testECIES_1(const std::string &message, CurveType c_type){
    const Curve *curv = GetCurveParam(c_type);

    std::string plain;
    std::string cypher;
    std::string iv;

    BN priv = RandomBNLt(curv->n);
    CurvePoint pub = curv->g * priv;

    bool ok = true;
    ECIES enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(pub, message, iv, cypher);
    EXPECT_TRUE(ok);
    show_mem("cypher: ", cypher.c_str(), cypher.length());
    ok = enc.Decrypt(priv, cypher, iv, plain);
    EXPECT_TRUE(ok);
    show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < message.length(); i ++){
        EXPECT_EQ(message[i], plain[i]);
    }
}

TEST(Curve_ENC, ECIES)
{
    for(size_t i = 0; i < message_arr.size(); i++){
        testECIES_0(message_arr[i], CurveType::P256);
        testECIES_1(message_arr[i], CurveType::P256);
    }
    for(size_t i = 0; i < message_arr.size(); i++){
        testECIES_0(message_arr[i], CurveType::SECP256K1);
        testECIES_1(message_arr[i], CurveType::SECP256K1);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
