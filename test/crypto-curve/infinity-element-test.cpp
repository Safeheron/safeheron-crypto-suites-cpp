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

void testInifnity(CurveType type)
{
    CurvePoint a(type);
    std::string bytes1;
    std::string bytes2;
    a.EncodeFull(bytes1);
    a.EncodeCompressed(bytes2);
    EXPECT_TRUE(a.IsInfinity());
    EXPECT_TRUE(bytes1.length() == 1 && bytes1[0] == 0x00);
    EXPECT_TRUE(bytes2.length() == 1 && bytes2[0] == 0x00);
    EXPECT_TRUE(a.DecodeFull(bytes1, type));
    EXPECT_TRUE(a.IsInfinity());
    EXPECT_TRUE(a.DecodeCompressed(bytes2, type));
    EXPECT_TRUE(a.IsInfinity());
}

TEST(CurvePoint, Infinity)
{
    testInifnity(CurveType::SECP256K1);
    testInifnity(CurveType::P256);
#if ENABLE_STARK
    testInifnity(CurveType::STARK);
#endif // ENABLE_STARK
    testInifnity(CurveType::ED25519);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
