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

void testRelationOperations(CurvePoint CPoint0, CurvePoint CPointEqual, CurvePoint CPointNeg, CurvePoint CPointNotEqual) {
    EXPECT_TRUE(CPoint0 == CPointEqual);
    EXPECT_FALSE(CPoint0 == CPointNotEqual);
    EXPECT_TRUE(CPoint0.Neg() == CPointNeg);
    EXPECT_TRUE(CPointNeg.Neg() == CPoint0);
    EXPECT_TRUE(CPoint0 !=  CPointNotEqual);
    EXPECT_FALSE(CPoint0 != CPointEqual);
    EXPECT_TRUE(CPoint0 != CPointNeg);
    CurvePoint Zero = CPointEqual + CPointNeg;
    EXPECT_TRUE(Zero.IsInfinity());
    CurvePoint CPoint1 = CPoint0 + Zero;
    EXPECT_TRUE(CPoint1 == CPoint0);
    CPoint1 = CPoint0 - Zero;
    EXPECT_TRUE(CPoint1 == CPoint0);
    CPoint0 += Zero;
    EXPECT_TRUE(CPoint1 == CPoint0);
    CPoint0 -= Zero;
    EXPECT_TRUE(CPoint1 == CPoint0);
    EXPECT_TRUE(Zero.Neg() == Zero);
    EXPECT_TRUE(Zero.Neg().IsInfinity());
}
TEST(CurvePoint, RelationOperations) {
    BN bn_x("b976f8c0cbe611898a46813f7f1862452fcef6750f0fe0f33b09f9554ebe3270", 16);
    BN bn_y("def6459ac8569fa0fdc2bf43a0687cec97c604cc392c6af1364f87b2c312400b", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    CurvePoint CPoint0(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    bn_x = BN("fb9d980df15a4ba29a7683c734ec061c776cc793cad79147f2d591bbfb8ac165", 16);
    bn_y = BN("141ec7cd74fada18d910d895c63ceb72eedf8e876a3846d73218da39743297b0", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    CurvePoint CPointNotEqual(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    bn_x = BN("b976f8c0cbe611898a46813f7f1862452fcef6750f0fe0f33b09f9554ebe3270", 16);
    bn_y = BN("2109ba6537a9605f023d40bc5f9783136839fb33c6d3950ec9b0784c3cedbc24", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    CurvePoint CPointNeg(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    testRelationOperations(CPoint0, CPoint0, CPointNeg, CPointNotEqual);

    bn_x = BN("d5b8544ada438d5d5c7803b14f94a210316356a838b8cf9032020f234eb7aff9", 16);
    bn_y = BN("beee97008a7d0ceb6ea2912f049c35b17db6362f214c0767f8ee0ad6720cbe42", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    CPoint0 = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::P256);
    bn_x = BN("bcbd5c51dce4a6d8efa93416b03a57467efca87c534337185ee728429bbd37bb", 16);
    bn_y = BN("6e10e0c463c046811b9aa410f0a3df9a738a9fdac1438694cee7302fdd3c6a95", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    CPointNotEqual = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::P256);
    bn_x = BN("d5b8544ada438d5d5c7803b14f94a210316356a838b8cf9032020f234eb7aff9", 16);
    bn_y = BN("411168fe7582f315915d6ed0fb63ca4e8249c9d1deb3f8980711f5298df341bd", 16);
//    bn_x = BN("d5b8544ada438d5d5c7803b14f94a210316356a838b8cf9032020f234eb7aff9", 16);
//    bn_y = BN("-beee97008a7d0ceb6ea2912f049c35b17db6362f214c0767f8ee0ad6720cbe42", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    CPointNeg = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::P256);
    testRelationOperations(CPoint0, CPoint0, CPointNeg, CPointNotEqual);

    bn_x = BN("41a237fc99f4e91d48fa1cda69a3b5087b0b4ba2ee8bb28be2f377252968f159", 16);
    bn_y = BN("1f3df43b1b2a09127cc4f9dfa68a0b1f5e6f619780a668079471d5f3935ff65", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    CPoint0 = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    bn_x = BN("523de6af479614ab27f0913253dd72749d0964472d03d970100c35944dd84fa7", 16);
    bn_y = BN("9f0af2b712abad5297c46c7464114c828305bfbada03f656f954822851dcc8f", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    CPointNotEqual = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    bn_x = BN("3e5dc803660b16e2b705e325965c4af784f4b45d11744d741d0c88dad6970e94", 16);
    bn_y = BN("1f3df43b1b2a09127cc4f9dfa68a0b1f5e6f619780a668079471d5f3935ff65", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    CPointNeg = CurvePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    testRelationOperations(CPoint0, CPoint0, CPointNeg, CPointNotEqual);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
