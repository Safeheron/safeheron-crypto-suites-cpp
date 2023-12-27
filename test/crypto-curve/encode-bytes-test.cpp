#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/hex.h"
#include "crypto-curve/curve.h"
#include "crypto-curve/eddsa.h"


using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

void testEncodeAndDecode(BN bn_x, BN bn_y, CurveType cType, std::string pub33_expected, std::string pub65_expected) {
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, cType));
    CurvePoint CPoint0;
    CurvePoint CPoint1(bn_x, bn_y, cType);
    CurvePoint CPoint2;
    CPoint2.DecodeCompressed((unsigned char*)safeheron::encode::hex::DecodeFromHex(pub33_expected).c_str(), cType);
    EXPECT_TRUE(CPoint1 == CPoint2);
    CPoint2 = CPoint0;
    CPoint2.DecodeFull((unsigned char*)safeheron::encode::hex::DecodeFromHex(pub65_expected).c_str(), cType);
    EXPECT_TRUE(CPoint1 == CPoint2);
    uint8_t pub33[33];
    std::string pub33_hex;
    CPoint1.EncodeCompressed(pub33);
    pub33_hex = safeheron::encode::hex::EncodeToHex(pub33, 33);
    EXPECT_TRUE(strncasecmp(pub33_hex.c_str(), pub33_expected.c_str(), 66) == 0);
    //  EXPECT_TRUE(pub33_hex = pub33_expected);
    uint8_t pub65[65];
    std::string pub65_hex;
    CPoint1.EncodeFull(pub65);
    pub65_hex = safeheron::encode::hex::EncodeToHex(pub65, 65);
    EXPECT_TRUE(strncasecmp(pub65_hex.c_str(), pub65_expected.c_str(), 130) == 0);
    //  EXPECT_TRUE(pub65_hex = pub65_expected);

}
TEST(CurvePoint, EncodeAndDecode) {
    BN bn_x("2706b694c418ff5bbab8e45b66d2910c5c43dc841bcd05b00f5d6057f33eefaa", 16);
    BN bn_y("51d407250de8dc72038ef62f4996ad1a05fdb17210a479b3da233cbee138c247", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    std::string pub33_expected = "032706b694c418ff5bbab8e45b66d2910c5c43dc841bcd05b00f5d6057f33eefaa";
    std::string pub65_expected = "042706b694c418ff5bbab8e45b66d2910c5c43dc841bcd05b00f5d6057f33eefaa51d407250de8dc72038ef62f4996ad1a05fdb17210a479b3da233cbee138c247";
    testEncodeAndDecode(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1, pub33_expected, pub65_expected);

    bn_x = BN("5211997064dab18a9a4f95e49686289676172e0a679f18ac88651c8ac91e15b8", 16);
    bn_y = BN("2968ff81973becbde9abaacb61478313c28663d8635542946bd2349e5cb4eb12", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    pub33_expected = "025211997064dab18a9a4f95e49686289676172e0a679f18ac88651c8ac91e15b8";
    pub65_expected = "045211997064dab18a9a4f95e49686289676172e0a679f18ac88651c8ac91e15b82968ff81973becbde9abaacb61478313c28663d8635542946bd2349e5cb4eb12";
    testEncodeAndDecode(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1, pub33_expected, pub65_expected);

    bn_x = BN("b6679ce9ab4423d995ba4ccb569fd37455cc939d332f296cfdd1f1699f1bf7df", 16);
    bn_y = BN("2fa22f9ad7fc0dc25743c8713ad990099e66f26b237933dfa967c349ded011fb", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    pub33_expected = "03b6679ce9ab4423d995ba4ccb569fd37455cc939d332f296cfdd1f1699f1bf7df";
    pub65_expected = "04b6679ce9ab4423d995ba4ccb569fd37455cc939d332f296cfdd1f1699f1bf7df2fa22f9ad7fc0dc25743c8713ad990099e66f26b237933dfa967c349ded011fb";
    testEncodeAndDecode(bn_x, bn_y, safeheron::curve::CurveType::P256, pub33_expected, pub65_expected);

    bn_x = BN("14ee50102f71a4c56d44dd452a1aa3524a2abcc5f92d51c473e0f86575186257", 16);
    bn_y = BN("dca32beb02cb0d390ac1695c67cf06ec3b00f6067c4e53cb8906a9e946dfdcb2", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    pub33_expected = "0214ee50102f71a4c56d44dd452a1aa3524a2abcc5f92d51c473e0f86575186257";
    pub65_expected = "0414ee50102f71a4c56d44dd452a1aa3524a2abcc5f92d51c473e0f86575186257dca32beb02cb0d390ac1695c67cf06ec3b00f6067c4e53cb8906a9e946dfdcb2";
    testEncodeAndDecode(bn_x, bn_y, safeheron::curve::CurveType::P256, pub33_expected, pub65_expected);

    bn_x = BN("4f9ca2ceda569dae98d470fc43ec2dd4b11318b643f40e1b8275533f55e68145", 16);
    bn_y = BN("381087ddb46728371311bb536b7765387878d016c7315f802a4b0b462395e6c1", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    pub33_expected = "034f9ca2ceda569dae98d470fc43ec2dd4b11318b643f40e1b8275533f55e68145";
    pub65_expected = "044f9ca2ceda569dae98d470fc43ec2dd4b11318b643f40e1b8275533f55e68145381087ddb46728371311bb536b7765387878d016c7315f802a4b0b462395e6c1";
    testEncodeAndDecode(bn_x, bn_y, safeheron::curve::CurveType::ED25519, pub33_expected, pub65_expected);

    bn_x = BN("1a276770f3f04a7bf33ec6726d1b4da3239b3b93b8cd6355b7add64260965bee", 16);
    bn_y = BN("03be31597a8ba0cf943af84d9380a88eeb4691c0cfcfcacf27404418ecee6dfa", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    pub33_expected = "021a276770f3f04a7bf33ec6726d1b4da3239b3b93b8cd6355b7add64260965bee";
    pub65_expected = "041a276770f3f04a7bf33ec6726d1b4da3239b3b93b8cd6355b7add64260965bee03be31597a8ba0cf943af84d9380a88eeb4691c0cfcfcacf27404418ecee6dfa";
    testEncodeAndDecode(bn_x, bn_y, safeheron::curve::CurveType::ED25519, pub33_expected, pub65_expected);
}

void testEdwardsEncodeAndDecode(BN bn_x, BN bn_y, std::string pub_expected, CurveType cType) {

    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, cType));
    CurvePoint CPoint0;
    CurvePoint CPoint1(bn_x, bn_y, cType);
    CPoint0.DecodeEdwardsPoint((unsigned char*)safeheron::encode::hex::DecodeFromHex(pub_expected).c_str(), cType);
    EXPECT_TRUE(CPoint0 == CPoint1);
    uint8_t pub[32];
    std::string pub_hex;
    CPoint1.EncodeEdwardsPoint(pub);
    pub_hex = safeheron::encode::hex::EncodeToHex(pub, 32);
    EXPECT_TRUE(strncasecmp(pub_hex.c_str(), pub_expected.c_str(), 64) == 0);
}

TEST(CurvePoint, EdwardsEncodeAndDecode) {
    BN bn_x("72e5ace826fb33f91490162c8c62cdcfdf220d12b869359d5f8d81d585be30bb", 16);
    BN bn_y("70582dca509254d9f8a77ccb181f7eb23a17126d5f86f2f77d7676db5f67508e", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    std::string pub_expected = "8e50675fdb76767df7f2865f6d12173ab27e1f18cb7ca7f8d9549250ca2d58f0";
    testEdwardsEncodeAndDecode(bn_x, bn_y, pub_expected, safeheron::curve::CurveType::ED25519);
    bn_x = BN("6480476fe9911ddd260a0d4212d934ae1f352e2ccd9fea9cc78cf9460dcb2d82", 16);
    bn_y = BN("3a6fc16d4debdca41b14644fd06dec1d449c4816f999ba09ecf5edca3ee8694a", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    pub_expected = "4a69e83ecaedf5ec09ba99f916489c441dec6dd04f64141ba4dceb4d6dc16f3a";
    testEdwardsEncodeAndDecode(bn_x, bn_y, pub_expected, safeheron::curve::CurveType::ED25519);
}

void testUniverseEncode(const char *x_hex, const char *y_hex, const std::string &pub33_hex, const std::string &pub65_hex, CurveType cType){
    CurvePoint point;
    BN x(x_hex, 16);
    BN y(y_hex, 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(x, y, cType));
    EXPECT_TRUE(point.PointFromX(x, y.IsOdd(), cType));
    CurvePoint p1(x, y, cType); // Be careful! "CurvePoint::ValidatePoint" should be invoked firstly.
    EXPECT_TRUE(point == p1);
    std::string str;
    //p1.x().ToHexStr(str);
    //std::cout << "p1.x: " << str << std::endl;
    //p1.y().ToHexStr(str);
    //std::cout << "p1.y: " << str << std::endl;
    //point.x().ToHexStr(str);
    //std::cout << "point.x: " << str << std::endl;
    //point.y().ToHexStr(str);
    //std::cout << "point.y: " << str << std::endl;

    // Decode compressed public key, of which the length is 33.
    CurvePoint p2;
    std::string b33 = safeheron::encode::hex::DecodeFromHex(pub33_hex);
    EXPECT_TRUE(p2.DecodeCompressed(reinterpret_cast<const uint8_t *>(b33.c_str()), cType));
    EXPECT_TRUE(p1 == p2);
    //p2.x().ToHexStr(str);
    //std::cout << "p2.x: " << str << std::endl;
    //p2.y().ToHexStr(str);
    //std::cout << "p2.y: " << str << std::endl;

    // Encode compressed public key, of which the length is 33.
    uint8_t out_b33[33];
    p2.EncodeCompressed(out_b33);
    std::string out_pub33_hex = safeheron::encode::hex::EncodeToHex(out_b33, 33);
    EXPECT_TRUE(strncasecmp(pub33_hex.c_str(), out_pub33_hex.c_str(), 66) == 0);
    //std::cout << pub33_hex << std::endl;
    //std::cout << out_pub33_hex << std::endl;

    // Decode full public key, of which the length is 65.
    CurvePoint p3;
    std::string b65 = safeheron::encode::hex::DecodeFromHex(pub65_hex);
    EXPECT_TRUE(p3.DecodeFull(reinterpret_cast<const uint8_t *>(b65.c_str()), cType));
    EXPECT_TRUE(p1 == p3);

    // Encode full public key, of which the length is 65.
    uint8_t out_b65[65];
    p3.EncodeFull(out_b65);
    std::string out_pub65_hex = safeheron::encode::hex::EncodeToHex(out_b65, 65);
    EXPECT_TRUE(strncasecmp(pub65_hex.c_str(), out_pub65_hex.c_str(), 130) == 0);
    //std::cout << pub65_hex << std::endl;
    //std::cout << out_pub65_hex << std::endl;
}

TEST(CurvePoint, UniverseEncode)
{
    testUniverseEncode("a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                       "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
                       "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                       "04a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
                       CurveType::SECP256K1);
    testUniverseEncode("cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f",
                       "878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773",
                       "03cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f",
                       "04cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773",
                       CurveType::P256);
    testUniverseEncode("602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
                       "637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
                       "02602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
                       "04602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
                       CurveType::ED25519);
#if ENABLE_STARK
    testUniverseEncode("03909690e1123c80678a7ba0fde0e8447f6f02b3f6b960034d1e93524f8b476",
                       "07122e9063d239d89d4e336753845b76f2b33ca0d7f0c1acd4b9fe974994cc19",
                       "03003909690e1123c80678a7ba0fde0e8447f6f02b3f6b960034d1e93524f8b476",
                       "04003909690e1123c80678a7ba0fde0e8447f6f02b3f6b960034d1e93524f8b47607122e9063d239d89d4e336753845b76f2b33ca0d7f0c1acd4b9fe974994cc19",
                       CurveType::STARK);
#endif // ENABLE_STARK
}

void testEdwardsEncode(const char *x_hex, const char *y_hex, const std::string &pub32_hex, CurveType cType){
    CurvePoint point;
    BN x(x_hex, 16);
    BN y(y_hex, 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(x, y, cType));
    EXPECT_TRUE(point.PointFromX(x, y.IsOdd(), cType));
    CurvePoint p1(x, y, cType); // Be careful! "CurvePoint::ValidatePoint" should be invoked firstly.
    EXPECT_TRUE(point == p1);
    std::string str;
    //p1.x().ToHexStr(str);
    //std::cout << "p1.x: " << str << std::endl;
    //p1.y().ToHexStr(str);
    //std::cout << "p1.y: " << str << std::endl;
    //point.x().ToHexStr(str);
    //std::cout << "point.x: " << str << std::endl;
    //point.y().ToHexStr(str);
    //std::cout << "point.y: " << str << std::endl;

    // Decode compressed public key, of which the length is 33.
    CurvePoint p2;
    std::string b32 = safeheron::encode::hex::DecodeFromHex(pub32_hex);
    EXPECT_TRUE(p2.DecodeEdwardsPoint((uint8_t *) b32.c_str(), cType));
    EXPECT_TRUE(p1 == p2);
    //p2.x().ToHexStr(str);
    //std::cout << "p2.x: " << str << std::endl;
    //p2.y().ToHexStr(str);
    //std::cout << "p2.y: " << str << std::endl;

    // Encode compressed public key, of which the length is 33.
    uint8_t out_b32[32];
    p2.EncodeEdwardsPoint(out_b32);
    std::string out_pub32_hex = safeheron::encode::hex::EncodeToHex(out_b32, 32);
    EXPECT_TRUE(strncasecmp(pub32_hex.c_str(), out_pub32_hex.c_str(), 66) == 0);
    //std::cout << pub32_hex << std::endl;
    //std::cout << out_pub32_hex << std::endl;

}

TEST(CurvePoint, EncodeEdwards)
{
    testEdwardsEncode("602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
                      "637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
                      "2c7be86ab07488ba43e8e03d85a67625cfbf98c8544de4c877241b7aaafc7fe3",
                      CurveType::ED25519);
    testEdwardsEncode("4b87a1147457b111116b878cfc2312de451370ac38fe8690876ef6ac346fd47",
                      "405ea0cdd414bda960318b3108769a8928a25b756c372b254c69c78ea2fd81c5",
                      "c581fda28ec7694c252b376c755ba228899a7608318b3160a9bd14d4cda05ec0",
                      CurveType::ED25519);
    testEdwardsEncode("7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
                      "ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7",
                      "e7caaa83373a94afae43fec59b447c99ba282b19a7616c24c785ad8966a1e10e",
                      CurveType::ED25519);
}

void testEncodeCompressed(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    for (int i = 0; i < 10; ++i) {
        BN r = safeheron::rand::RandomBNLt(curv->n);
        CurvePoint p0 = curv->g * r;
        CurvePoint p1(cType);
        std::string hex0, hex1;

        std::string bytes;
        // p0 => bytes => hex0
        p0.EncodeCompressed(bytes);
        hex0 = safeheron::encode::hex::EncodeToHex(bytes);
        std::cout << "p0: " << hex0 << std::endl;
        // bytes => p1
        EXPECT_TRUE(p1.DecodeCompressed(bytes, cType));
        // p1 => bytes => hex1
        p1.EncodeCompressed(bytes);
        hex1 = safeheron::encode::hex::EncodeToHex(bytes);
        std::cout << "p1: " << hex1 << std::endl;
        // p0 == p1
        EXPECT_TRUE(p0 == p1);
        // hex0 = hex1
        EXPECT_TRUE(hex0 == hex1);
    }
}


void testEncodeFull(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    for (int i = 0; i < 10; ++i) {
        BN r = safeheron::rand::RandomBNLt(curv->n);
        CurvePoint p0 = curv->g * r;
        CurvePoint p1(cType);
        std::string hex0, hex1;

        std::string bytes;
        // p0 => bytes => hex0
        p0.EncodeFull(bytes);
        hex0 = safeheron::encode::hex::EncodeToHex(bytes);
        std::cout << "p0: " << hex0 << std::endl;
        // bytes => p1
        EXPECT_TRUE(p1.DecodeFull(bytes, cType));
        // p1 => bytes => hex1
        p1.EncodeFull(bytes);
        hex1 = safeheron::encode::hex::EncodeToHex(bytes);
        std::cout << "p1: " << hex1 << std::endl;
        // p0 == p1
        EXPECT_TRUE(p0 == p1);
        // hex0 = hex1
        EXPECT_TRUE(hex0 == hex1);
    }
}

void testEncodeEdwards(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    for (int i = 0; i < 10; ++i) {
        BN r = safeheron::rand::RandomBNLt(curv->n);
        CurvePoint p0 = curv->g * r;
        CurvePoint p1(cType);
        std::string hex0, hex1;

        std::string bytes;
        // p0 => bytes => hex0
        p0.EncodeEdwardsPoint(bytes);
        hex0 = safeheron::encode::hex::EncodeToHex(bytes);
        std::cout << "p0: " << hex0 << std::endl;
        // bytes => p1
        EXPECT_TRUE(p1.DecodeEdwardsPoint(bytes, cType));
        // p1 => bytes => hex1
        p1.EncodeEdwardsPoint(bytes);
        hex1 = safeheron::encode::hex::EncodeToHex(bytes);
        std::cout << "p1: " << hex1 << std::endl;
        // p0 == p1
        EXPECT_TRUE(p0 == p1);
        // hex0 = hex1
        EXPECT_TRUE(hex0 == hex1);
    }
}

TEST(CurvePoint, EncodeBytes_2)
{
    testEncodeCompressed(CurveType::SECP256K1);
    testEncodeCompressed(CurveType::P256);
#if ENABLE_STARK
    testEncodeCompressed(CurveType::STARK);
#endif // ENABLE_STARK
    testEncodeCompressed(CurveType::ED25519);

    testEncodeFull(CurveType::SECP256K1);
    testEncodeFull(CurveType::P256);
#if ENABLE_STARK
    testEncodeFull(CurveType::STARK);
#endif // ENABLE_STARK
    testEncodeFull(CurveType::ED25519);

    testEncodeEdwards(CurveType::ED25519);
}

void testEncodeCompressed_OldVersion(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    for (int i = 0; i < 10; ++i) {
        BN r = safeheron::rand::RandomBNLt(curv->n);
        CurvePoint p0 = curv->g * r;
        CurvePoint p1(cType);
        std::string hex0, hex1;

        uint8_t bytes[33];
        // p0 => bytes => hex0
        p0.EncodeCompressed(bytes);
        hex0 = safeheron::encode::hex::EncodeToHex(bytes, 33);
        std::cout << "p0: " << hex0 << std::endl;
        // bytes => p1
        EXPECT_TRUE(p1.DecodeCompressed(bytes, cType));
        // p1 => bytes => hex1
        p1.EncodeCompressed(bytes);
        hex1 = safeheron::encode::hex::EncodeToHex(bytes, 33);
        std::cout << "p1: " << hex1 << std::endl;
        // p0 == p1
        EXPECT_TRUE(p0 == p1);
        // hex0 = hex1
        EXPECT_TRUE(hex0 == hex1);
    }
}


void testEncodeFull_OldVersion(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    for (int i = 0; i < 10; ++i) {
        BN r = safeheron::rand::RandomBNLt(curv->n);
        CurvePoint p0 = curv->g * r;
        CurvePoint p1(cType);
        std::string hex0, hex1;

        uint8_t bytes[65];
        // p0 => bytes => hex0
        p0.EncodeFull(bytes);
        hex0 = safeheron::encode::hex::EncodeToHex(bytes, 65);
        std::cout << "p0: " << hex0 << std::endl;
        // bytes => p1
        EXPECT_TRUE(p1.DecodeFull(bytes, cType));
        // p1 => bytes => hex1
        p1.EncodeFull(bytes);
        hex1 = safeheron::encode::hex::EncodeToHex(bytes, 65);
        std::cout << "p1: " << hex1 << std::endl;
        // p0 == p1
        EXPECT_TRUE(p0 == p1);
        // hex0 = hex1
        EXPECT_TRUE(hex0 == hex1);
    }
}

void testEncodeEdwards_OldVersion(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    for (int i = 0; i < 10; ++i) {
        BN r = safeheron::rand::RandomBNLt(curv->n);
        CurvePoint p0 = curv->g * r;
        CurvePoint p1(cType);
        std::string hex0, hex1;

        uint8_t bytes[32];
        // p0 => bytes => hex0
        p0.EncodeEdwardsPoint(bytes);
        hex0 = safeheron::encode::hex::EncodeToHex(bytes, 32);
        std::cout << "p0: " << hex0 << std::endl;
        // bytes => p1
        EXPECT_TRUE(p1.DecodeEdwardsPoint(bytes, cType));
        // p1 => bytes => hex1
        p1.EncodeEdwardsPoint(bytes);
        hex1 = safeheron::encode::hex::EncodeToHex(bytes, 32);
        std::cout << "p1: " << hex1 << std::endl;
        // p0 == p1
        EXPECT_TRUE(p0 == p1);
        // hex0 = hex1
        EXPECT_TRUE(hex0 == hex1);
    }
}

TEST(CurvePoint, EncodeBytes_1)
{
    testEncodeCompressed_OldVersion(CurveType::SECP256K1);
    testEncodeCompressed_OldVersion(CurveType::P256);
#if ENABLE_STARK
    testEncodeCompressed_OldVersion(CurveType::STARK);
#endif // ENABLE_STARK
    testEncodeCompressed_OldVersion(CurveType::ED25519);

    testEncodeFull_OldVersion(CurveType::SECP256K1);
    testEncodeFull_OldVersion(CurveType::P256);
#if ENABLE_STARK
    testEncodeFull_OldVersion(CurveType::STARK);
#endif // ENABLE_STARK
    testEncodeFull_OldVersion(CurveType::ED25519);

    testEncodeEdwards_OldVersion(CurveType::ED25519);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
