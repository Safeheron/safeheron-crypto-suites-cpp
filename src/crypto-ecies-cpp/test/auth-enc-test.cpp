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

void testAuthEnc(const std::string &message, CurveType c_type){
    const Curve *curv = GetCurveParam(c_type);

    std::string plain;
    std::string cypher;

    BN priv1 = RandomBNLt(curv->n);
    CurvePoint pub1 = curv->g * priv1;

    BN priv2 = RandomBNLt(curv->n);
    CurvePoint pub2 = curv->g * priv2;

    bool ok = true;
    AuthEnc enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(priv1, pub2, message, cypher);
    EXPECT_TRUE(ok);
    if(ok) show_mem("cypher: ", cypher.c_str(), cypher.length());

    ok = enc.Decrypt(priv2, pub1, cypher, plain);
    show_mem("plain : ", plain.c_str(), plain.length());
    EXPECT_TRUE(ok);
    if(ok) show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < message.length(); i ++){
        //EXPECT_EQ(message[i], plain[i]);
    }
}

TEST(Curve_ENC, AuthEnc)
{
    for(size_t i = 0; i < message_arr.size(); i++){
        testAuthEnc(message_arr[i], CurveType::P256);
    }
    for(size_t i = 0; i < message_arr.size(); i++){
        testAuthEnc(message_arr[i], CurveType::SECP256K1);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
