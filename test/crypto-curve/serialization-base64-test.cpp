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

TEST(CurvePoint, FromAndTo) {
    CurvePoint p0;
    std::string base64;
    std::string json_str;

    BN bn_x("d50743c0183b28d5f98edfab36aad6c2a5cc76b59a5b6e8dfbe79d597c68f1a5", 16);
    BN bn_y("5d78cd25b517f480dfb4af9319ce6feb0a8ff3640b440128d46cd9d2530b763d", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    CurvePoint p1(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    EXPECT_TRUE(p1.ToBase64(base64));
    EXPECT_TRUE(p0.FromBase64(base64));
    EXPECT_TRUE(p1 == p0);

    bn_x = BN("14ee50102f71a4c56d44dd452a1aa3524a2abcc5f92d51c473e0f86575186257", 16);
    bn_y = BN("dca32beb02cb0d390ac1695c67cf06ec3b00f6067c4e53cb8906a9e946dfdcb2", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    CurvePoint p2(bn_x, bn_y, safeheron::curve::CurveType::P256);
    EXPECT_TRUE(p2.ToBase64(base64));
    EXPECT_TRUE(p0.FromBase64(base64));
    EXPECT_TRUE(p2 == p0);

    bn_x = BN("4f9ca2ceda569dae98d470fc43ec2dd4b11318b643f40e1b8275533f55e68145", 16);
    bn_y = BN("381087ddb46728371311bb536b7765387878d016c7315f802a4b0b462395e6c1", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    CurvePoint p3(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    EXPECT_TRUE(p3.ToBase64(base64));
    EXPECT_TRUE(p0.FromBase64(base64));
    EXPECT_TRUE(p3 == p0);
}

void testSerialize(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    // base64 encode
    CurvePoint p0 = curv->g * 10;
    CurvePoint p1(cType);

    std::string base64;
    // p0 => json
    EXPECT_TRUE(p0.ToBase64(base64));
    std::cout << "p0: " << base64 << std::endl;
    // json => p1
    EXPECT_TRUE(p1.FromBase64(base64));
    // p1 => json
    EXPECT_TRUE(p1.ToBase64(base64));
    std::cout << "p1: " << base64 << std::endl;
    // p0 == p1
    EXPECT_TRUE(p0 == p1);
}

void testSerializeInfinityPoint(CurveType cType){
    CurvePoint p0(cType);
    CurvePoint p1;

    std::string base64_1;
    std::string base64_2;
    // p0 => json
    EXPECT_TRUE(p0.ToBase64(base64_1));
    std::cout << "p0: " << base64_1 << std::endl;
    // json => p1
    EXPECT_TRUE(p1.FromBase64(base64_1));
    // p1 => json
    EXPECT_TRUE(p1.ToBase64(base64_2));
    std::cout << "p1: " << base64_2 << std::endl;
    // p0 == p1
    EXPECT_TRUE(p0 == p1);
    EXPECT_TRUE(base64_1 == base64_2);
    EXPECT_TRUE(p1.IsInfinity());
}

TEST(CurvePoint, Serialize)
{
    testSerialize(CurveType::SECP256K1);
    testSerialize(CurveType::P256);
    testSerialize(CurveType::ED25519);
#if ENABLE_STARK
    testSerialize(CurveType::STARK);
#endif // ENABLE_STARK

    testSerializeInfinityPoint(CurveType::SECP256K1);
    testSerializeInfinityPoint(CurveType::P256);
    testSerializeInfinityPoint(CurveType::ED25519);
#if ENABLE_STARK
    testSerializeInfinityPoint(CurveType::STARK);
#endif // ENABLE_STARK
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
