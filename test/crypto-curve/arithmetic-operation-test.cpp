#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-curve/eddsa.h"


using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

TEST(CurvePoint, AddAndMul_SECP256k1) {
    //SECP256k1 Curve
    CurvePoint CPoint0 = safeheron::curve::GetCurveParam(safeheron::curve::CurveType::SECP256K1)->g;

    BN bn0("ff0c", 16);
    CurvePoint CPoint1 = CPoint0 * bn0 ;
    BN bn_x("d50743c0183b28d5f98edfab36aad6c2a5cc76b59a5b6e8dfbe79d597c68f1a5", 16);
    BN bn_y("5d78cd25b517f480dfb4af9319ce6feb0a8ff3640b440128d46cd9d2530b763d", 16);
    CurvePoint CPointExpected(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    EXPECT_TRUE(CPoint1 == CPointExpected);

    BN bn1("2ff0", 16);
    CurvePoint CPoint2 = CPoint0 * bn0 * bn1;
    CurvePoint CPoint3 = CPoint1 * bn1;
    bn_x = BN("d23f2543dc853556d1908d6236dd34e41d167d813b8b3a200c8cf99e6ca5771b", 16);
    bn_y = BN("384931ae3e529ca822c4e5a0527dac72356c7b32f352012bc2ad4de4673fbd56", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    EXPECT_TRUE(CPoint2 == CPointExpected);
    EXPECT_TRUE(CPoint3 == CPointExpected);

    CurvePoint CPoint4 = CPoint1 + CPoint2;
    bn_x = BN("cb6cddfa421930e131b298cdd0da12c511f26dfb74e6fbc151639091f08112bc", 16);
    bn_y = BN("ef57a9d1d59cb504fac7b31dd3be0548e8e29c543cfa16f91225d5bebf11d15b", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    EXPECT_TRUE(CPoint4 == CPointExpected);

    CurvePoint CPoint5 = CPoint2 + CPoint1 + CPoint0;
    bn_x = BN("53b0c14d14eb11ae07fff7c78dae89727a3199c39d08b3dfa8265b575af02065", 16);
    bn_y = BN("88d5be3ffef5311e2a47a622c81757c6d3078bdecd15947b9abde2500fc19565", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    EXPECT_TRUE(CPoint5 == CPointExpected);

    CurvePoint CPoint6 = CPoint1 * bn1 + CPoint0 * bn0 + CPoint0;
    EXPECT_TRUE(CPoint6 == CPoint5);

    CurvePoint CPoint7 = CPoint5 - CPoint2 - CPoint1;
    EXPECT_TRUE(CPoint7 == CPoint0);
    CPoint7 = CPoint5 - CPoint2 - CPoint0;
    EXPECT_TRUE(CPoint7 == CPoint1);
    CPoint7 = CPoint5 - CPoint1 - CPoint0;
    EXPECT_TRUE(CPoint7 == CPoint2);

    CurvePoint CPoint8 = CPoint0 * 65292 * 12272;
    EXPECT_TRUE(CPoint8 == CPoint2);
}

TEST(CurvePoint, AddAndMul_Equal_SECP256k1) {
    BN bn_x("cb6cddfa421930e131b298cdd0da12c511f26dfb74e6fbc151639091f08112bc", 16);
    BN bn_y("ef57a9d1d59cb504fac7b31dd3be0548e8e29c543cfa16f91225d5bebf11d15b", 16);
    CurvePoint CPoint0(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    bn_x = BN("fc9cbacaed0e1df50e9d81206bb55f2667e114e7303470308b333554d0735ad0", 16);
    bn_y = BN("d41fc02f2d4b3f74f4e9ec007a87954054d12fc93d53242c0a45bd38c75deb9e", 16);
    CurvePoint CPoint1(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    bn_x = BN("5211997064dab18a9a4f95e49686289676172e0a679f18ac88651c8ac91e15b8", 16);
    bn_y = BN("2968ff81973becbde9abaacb61478313c28663d8635542946bd2349e5cb4eb12", 16);
    CurvePoint CPoint2(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    CurvePoint CPoint3 = CPoint0;
    CPoint0 += CPoint1;
    EXPECT_TRUE(CPoint0 == CPoint2);
    CPoint0 -= CPoint1;
    EXPECT_TRUE(CPoint0 == CPoint3);
    //66ff88 -> 10: 6750088
    BN bn_scalar("66ff88", 16);
    bn_x = BN("fb9d980df15a4ba29a7683c734ec061c776cc793cad79147f2d591bbfb8ac165", 16);
    bn_y = BN("141ec7cd74fada18d910d895c63ceb72eedf8e876a3846d73218da39743297b0", 16);
    CurvePoint CPoint4(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    CPoint0 *= bn_scalar;
    EXPECT_TRUE(CPoint0 == CPoint4);
    CPoint0 = CPoint3;
    CPoint0 *= 6750088;
    EXPECT_TRUE(CPoint0 == CPoint4);
}

TEST(CurvePoint, AddAndMul_P256) {
    //P256 Curve
    CurvePoint CPoint0 = safeheron::curve::GetCurveParam(safeheron::curve::CurveType::P256)->g;

    BN bn0("ff0c", 16);
    CurvePoint CPoint1 = CPoint0 * bn0 ;
    BN bn_x("14ee50102f71a4c56d44dd452a1aa3524a2abcc5f92d51c473e0f86575186257", 16);
    BN bn_y("dca32beb02cb0d390ac1695c67cf06ec3b00f6067c4e53cb8906a9e946dfdcb2", 16);
    CurvePoint CPointExpected(bn_x, bn_y, safeheron::curve::CurveType::P256);
    EXPECT_TRUE(CPoint1 == CPointExpected);

    BN bn1("2ff0", 16);
    CurvePoint CPoint2 = CPoint0 * bn0 * bn1;
    CurvePoint CPoint3 = CPoint1 * bn1;
    bn_x = BN("bb37ba8f90e4472cec89a91b2d3074b85ae774f971c6697acb4564eb2007dbad", 16);
    bn_y = BN("da0afd2542f9303886b02953557e7c407a32b5efb66e2f7b71815b84725e7ff0", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::P256);
    EXPECT_TRUE(CPoint2 == CPointExpected);
    EXPECT_TRUE(CPoint3 == CPointExpected);

    CurvePoint CPoint4 = CPoint1 + CPoint2;
    bn_x = BN("60bb2588ca30263f20d6537ea7258398e06992cd46454ba94e0858c847b8757f", 16);
    bn_y = BN("5398d96d5acba43acf6b719f56a171ca0d2e8c313ea7631a39d2ec8ac183467b", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::P256);
    EXPECT_TRUE(CPoint4 == CPointExpected);

    CurvePoint CPoint5 = CPoint2 + CPoint1 + CPoint0;
    bn_x = BN("cdcbb1ad322ec2eea3944e8f02cf9893bffd7f217c9717c0a459a858b7c53828", 16);
    bn_y = BN("8f98c33f3d3f6d3ed68ee1de7488c0df6f8711d15138e6d169279b2427499783", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::P256);
    EXPECT_TRUE(CPoint5 == CPointExpected);

    CurvePoint CPoint6 = CPoint1 * bn1 + CPoint0 * bn0 + CPoint0;
    EXPECT_TRUE(CPoint6 == CPoint5);

    CurvePoint CPoint7 = CPoint5 - CPoint2 - CPoint1;
    EXPECT_TRUE(CPoint7 == CPoint0);
    CPoint7 = CPoint5 - CPoint2 - CPoint0;
    EXPECT_TRUE(CPoint7 == CPoint1);
    CPoint7 = CPoint5 - CPoint1 - CPoint0;
    EXPECT_TRUE(CPoint7 == CPoint2);

    CurvePoint CPoint8 = CPoint0 * 65292 * 12272;
    EXPECT_TRUE(CPoint8 == CPoint2);
}

TEST(CurvePoint, AddAndMul_Equal_P256) {
    BN bn_x("60bb2588ca30263f20d6537ea7258398e06992cd46454ba94e0858c847b8757f", 16);
    BN bn_y("5398d96d5acba43acf6b719f56a171ca0d2e8c313ea7631a39d2ec8ac183467b", 16);
    CurvePoint CPoint0(bn_x, bn_y, safeheron::curve::CurveType::P256);
    bn_x = BN("1b0ce2af8587a19b028108a534e281123b74a8c0528a2875d2321978bbba31c1", 16);
    bn_y = BN("c88448f4d4d83aca71df043ab6dd406300d06863b88a0a35bbfe0e29eccad2c2", 16);
    CurvePoint CPoint1(bn_x, bn_y, safeheron::curve::CurveType::P256);
    bn_x = BN("967d9403c820ede1423bfcacc35e0c48e1f67ed6a4aea304565f301907eece3a", 16);
    bn_y = BN("80e70922a5e357c105a625f47a4631f0054c11904743c1cbc7af2a8178e0baf5", 16);
    CurvePoint CPoint2(bn_x, bn_y, safeheron::curve::CurveType::P256);
    CurvePoint CPoint3 = CPoint0;
    CPoint0 += CPoint1;
    EXPECT_TRUE(CPoint0 == CPoint2);
    CPoint0 -= CPoint1;
    EXPECT_TRUE(CPoint0 == CPoint3);
    //66ff88 -> 10: 6750088
    BN bn_scalar("66ff88", 16);
    bn_x = BN("bcbd5c51dce4a6d8efa93416b03a57467efca87c534337185ee728429bbd37bb", 16);
    bn_y = BN("6e10e0c463c046811b9aa410f0a3df9a738a9fdac1438694cee7302fdd3c6a95", 16);
    CurvePoint CPoint4(bn_x, bn_y, safeheron::curve::CurveType::P256);
    CPoint0 *= bn_scalar;
    EXPECT_TRUE(CPoint0 == CPoint4);
    CPoint0 = CPoint3;
    CPoint0 *= 6750088;
    EXPECT_TRUE(CPoint0 == CPoint4);
}

TEST(CurvePoint, AddAndMul_ED25519) {
    //ED25519 Curve
    CurvePoint CPoint0 = safeheron::curve::GetCurveParam(safeheron::curve::CurveType::ED25519)->g;

    BN bn0("ff0c", 16);
    CurvePoint CPoint1 = CPoint0 * bn0 ;
    BN bn_x("4f9ca2ceda569dae98d470fc43ec2dd4b11318b643f40e1b8275533f55e68145", 16);
    BN bn_y("381087ddb46728371311bb536b7765387878d016c7315f802a4b0b462395e6c1", 16);
    CurvePoint CPointExpected(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    EXPECT_TRUE(CPoint1 == CPointExpected);

    BN bn1("2ff0", 16);
    CurvePoint CPoint2 = CPoint0 * bn0 * bn1;
    CurvePoint CPoint3 = CPoint1 * bn1;
    bn_x = BN("72e5ace826fb33f91490162c8c62cdcfdf220d12b869359d5f8d81d585be30bb", 16);
    bn_y = BN("70582dca509254d9f8a77ccb181f7eb23a17126d5f86f2f77d7676db5f67508e", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    EXPECT_TRUE(CPoint2 == CPointExpected);
    EXPECT_TRUE(CPoint3 == CPointExpected);

    CurvePoint CPoint4 = CPoint1 + CPoint2;
    bn_x = BN("32f4e867dda92f114dc9c966c53a7d4026d73070f9be5998000894e8fed2b927", 16);
    bn_y = BN("22ce5ddc1b8bf18b3afa29397da8c58ebe06c1aff40b9fc7bf54c20706965b50", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    EXPECT_TRUE(CPoint4 == CPointExpected);

    CurvePoint CPoint5 = CPoint2 + CPoint1 + CPoint0;
    bn_x = BN("6480476fe9911ddd260a0d4212d934ae1f352e2ccd9fea9cc78cf9460dcb2d82", 16);
    bn_y = BN("3a6fc16d4debdca41b14644fd06dec1d449c4816f999ba09ecf5edca3ee8694a", 16);
    CPointExpected = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    EXPECT_TRUE(CPoint5 == CPointExpected);

    CurvePoint CPoint6 = CPoint1 * bn1 + CPoint0 * bn0 + CPoint0;
    EXPECT_TRUE(CPoint6 == CPoint5);

    CurvePoint CPoint7 = CPoint5 - CPoint2 - CPoint1;
    EXPECT_TRUE(CPoint7 == CPoint0);
    CPoint7 = CPoint5 - CPoint2 - CPoint0;
    EXPECT_TRUE(CPoint7 == CPoint1);
    CPoint7 = CPoint5 - CPoint1 - CPoint0;
    EXPECT_TRUE(CPoint7 == CPoint2);

    CurvePoint CPoint8 = CPoint0 * 65292 * 12272;
    EXPECT_TRUE(CPoint8 == CPoint2);
}

TEST(CurvePoint, AddAndMul_Equal_ED25519) {
    BN bn_x("32f4e867dda92f114dc9c966c53a7d4026d73070f9be5998000894e8fed2b927", 16);
    BN bn_y("22ce5ddc1b8bf18b3afa29397da8c58ebe06c1aff40b9fc7bf54c20706965b50", 16);
    CurvePoint CPoint0(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    bn_x = BN("1dffbc8f74f74ee2edcd096f032c108c4d60f45c24016819660a40d63dd0f6d1", 16);
    bn_y = BN("7400dcf34fb2542d8d347e071d893e4dd4aaaf7a6b7c6b70adc66fef6ad956dc", 16);
    CurvePoint CPoint1(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    bn_x = BN("5c717922a5993da3ff7c8376349a9875ca9787dcb88ddaa6acfeb78338990df", 16);
    bn_y = BN("be532d32793f2956b1d1ab7c299f401924284ea02190772f43b49400fa25451", 16);
    CurvePoint CPoint2(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    CurvePoint CPoint3 = CPoint0;
    CPoint0 += CPoint1;
    EXPECT_TRUE(CPoint0 == CPoint2);
    CPoint0 -= CPoint1;
    EXPECT_TRUE(CPoint0 == CPoint3);
    //66ff88 -> 10: 6750088
    BN bn_scalar("66ff88", 16);
    bn_x = BN("523de6af479614ab27f0913253dd72749d0964472d03d970100c35944dd84fa7", 16);
    bn_y = BN("9f0af2b712abad5297c46c7464114c828305bfbada03f656f954822851dcc8f", 16);
    CurvePoint CPoint4(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    CPoint0 *= bn_scalar;
    EXPECT_TRUE(CPoint0 == CPoint4);
    CPoint0 = CPoint3;
    CPoint0 *= 6750088;
    EXPECT_TRUE(CPoint0 == CPoint4);
}

TEST(CurvePoint, Ed25519_Add_Mul)
{
    // p0 = g^10
    CurvePoint p0(BN("602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f", 16),
                  BN("637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c", 16),
                  CurveType::ED25519);
    // p0 = g^100
    CurvePoint p1(BN("4b87a1147457b111116b878cfc2312de451370ac38fe8690876ef6ac346fd47", 16),
                  BN("405ea0cdd414bda960318b3108769a8928a25b756c372b254c69c78ea2fd81c5", 16),
                  CurveType::ED25519);
    // p0 = g^1000
    CurvePoint p2(BN("7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e", 16),
                  BN("ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7", 16),
                  CurveType::ED25519);
    EXPECT_TRUE(p0 * 10 == p1);
    EXPECT_TRUE(p1 * 10 == p2);
    CurvePoint p3(CurveType::ED25519);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    EXPECT_TRUE(p3 == p1);
    CurvePoint p4(CurveType::ED25519);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    EXPECT_TRUE(p4 == p2);
    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::ED25519);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    EXPECT_TRUE(p5 == p1);
    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::ED25519);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    EXPECT_TRUE(p6 == p0);
}

TEST(CurvePoint, Secp256k1_Add_Mul)
{
    // p0 = g^10
    CurvePoint p0(BN("a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7", 16),
                  BN("893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7", 16),
                  CurveType::SECP256K1);
    // p0 = g^100
    CurvePoint p1(BN("ed3bace23c5e17652e174c835fb72bf53ee306b3406a26890221b4cef7500f88", 16),
                  BN("e57a6f571288ccffdcda5e8a7a1f87bf97bd17be084895d0fce17ad5e335286e", 16),
                  CurveType::SECP256K1);
    // p0 = g^1000
    CurvePoint p2(BN("4a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad", 16),
                  BN("baf1e702eb2a8badae14ba09a26a8ca7cb1127b64b2c39a1c7ba61f4a3c62601", 16),
                  CurveType::SECP256K1);
    EXPECT_TRUE(p0 * 10 == p1);
    EXPECT_TRUE(p1 * 10 == p2);
    CurvePoint p3(CurveType::SECP256K1);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    EXPECT_TRUE(p3 == p1);
    CurvePoint p4(CurveType::SECP256K1);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    EXPECT_TRUE(p4 == p2);
    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::SECP256K1);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    EXPECT_TRUE(p5 == p1);
    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::SECP256K1);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    EXPECT_TRUE(p6 == p0);
}

TEST(CurvePoint, P256_Add_Mul)
{
    // p0 = g^10
    CurvePoint p0(BN("cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f", 16),
                  BN("878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773", 16),
                  CurveType::P256);
    // p1 = g^100
    CurvePoint p1(BN("490a19531f168d5c3a5ae6100839bb2d1d920d78e6aeac3f7da81966c0f72170", 16),
                  BN("bbcd2f21db581bd5150313a57cfa2d9debe20d9f460117b588fcf9b0f4377794", 16),
                  CurveType::P256);
    // p2 = g^1000
    CurvePoint p2(BN("b8fa1a4acbd900b788ff1f8524ccfff1dd2a3d6c917e4009af604fbd406db702", 16),
                  BN("9a5cc32d14fc837266844527481f7f06cb4fb34733b24ca92e861f72cc7cae37", 16),
                  CurveType::P256);
    EXPECT_TRUE(p0 * 10 == p1);
    EXPECT_TRUE(p1 * 10 == p2);
    CurvePoint p3(CurveType::P256);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    EXPECT_TRUE(p3 == p1);
    CurvePoint p4(CurveType::P256);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    EXPECT_TRUE(p4 == p2);

    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::P256);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    EXPECT_TRUE(p5 == p1);
    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::P256);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    EXPECT_TRUE(p6 == p0);


    CurvePoint p7;
    EXPECT_TRUE(p7.PointFromXY(p1.x(), p1.y(), p1.GetCurveType()));
    EXPECT_TRUE(p7.PointFromXY(p2.x(), p2.y(), p2.GetCurveType()));
    EXPECT_TRUE(p7.PointFromXY(p3.x(), p3.y(), p3.GetCurveType()));
}

void testNeg(CurveType cType){
    CurvePoint zero(cType); // Initialize as zero
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    CurvePoint a = curv->g * 10;
    CurvePoint b = curv->g * 100;
    CurvePoint a_Neg = a.Neg();
    CurvePoint b_Neg = b.Neg();
    EXPECT_TRUE( a + a_Neg == zero);
    EXPECT_TRUE( b + b_Neg == zero);
}

TEST(CurvePoint, Neg)
{
    testNeg(CurveType::SECP256K1);
    testNeg(CurveType::P256);
    testNeg(CurveType::ED25519);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
