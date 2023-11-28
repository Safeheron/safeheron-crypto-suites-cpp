#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/hex.h"
#include "../src/crypto-curve/curve.h"
#include "../src/crypto-curve/eddsa.h"


using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

TEST(CurvePoint, Constructor) {
    CurvePoint CPoint0;
    EXPECT_FALSE(CPoint0.IsValid());
    EXPECT_FALSE(CPoint0.IsInfinity());
    std::cout << "CPoint0.Inspect(): " << CPoint0.Inspect() << std::endl;
    CurvePoint CPoint1(CPoint0);
    EXPECT_FALSE(CPoint1.IsValid());
    EXPECT_FALSE(CPoint1.IsInfinity());
    std::cout << "CPoint1.Inspect(): " << CPoint1.Inspect() << std::endl;
    CurvePoint CPoint2(CurveType::SECP256K1);
    EXPECT_TRUE(CPoint2.IsValid());
    EXPECT_TRUE(CPoint2.IsInfinity());
    std::cout << "CPoint2.Inspect(): " << CPoint2.Inspect() << std::endl;
    CurvePoint CPoint3(CurveType::P256);
    EXPECT_TRUE(CPoint3.IsValid());
    EXPECT_TRUE(CPoint3.IsInfinity());
    std::cout << "CPoint3.Inspect(): " << CPoint3.Inspect() << std::endl;
    CurvePoint CPoint4(CurveType::ED25519);
    EXPECT_TRUE(CPoint4.IsValid());
    EXPECT_TRUE(CPoint4.IsInfinity());
    std::cout << "CPoint4.Inspect(): " << CPoint4.Inspect() << std::endl;
    BN x("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    BN y("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    CurvePoint CPoint5(x, y, CurveType::SECP256K1);
    EXPECT_TRUE(CPoint5.IsValid());
    EXPECT_FALSE(CPoint5.IsInfinity());
    std::cout << "CPoint5.Inspect(): " << CPoint5.Inspect() << std::endl;
    x = BN("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6", 16);
    y = BN("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", 16);
    CurvePoint CPoint6(x, y, CurveType::P256);
    EXPECT_TRUE(CPoint6.IsValid());
    EXPECT_FALSE(CPoint6.IsInfinity());
    std::cout << "CPoint6.Inspect(): " << CPoint6.Inspect() << std::endl;
    x = BN("1a276770f3f04a7bf33ec6726d1b4da3239b3b93b8cd6355b7add64260965bee", 16);
    y = BN("3be31597a8ba0cf943af84d9380a88eeb4691c0cfcfcacf27404418ecee6dfa", 16);
    CurvePoint CPoint7(x, y, CurveType::ED25519);
    EXPECT_TRUE(CPoint7.IsValid());
    EXPECT_FALSE(CPoint7.IsInfinity());
    std::cout << "CPoint7.Inspect(): " << CPoint7.Inspect() << std::endl;
    CurvePoint CPoint8 = CPoint7;
    EXPECT_TRUE(CPoint8.IsValid());
    EXPECT_FALSE(CPoint8.IsInfinity());
    std::cout << "CPoint8.Inspect()(CPoint8 = CPoint7): " << CPoint8.Inspect() << std::endl;
    CPoint8 = CPoint5;
    EXPECT_TRUE(CPoint8.IsValid());
    EXPECT_FALSE(CPoint8.IsInfinity());
    std::cout << "CPoint8.Inspect()(CPoint8 = CPoint5): " << CPoint8.Inspect() << std::endl;

#if ENABLE_STARK
    CurvePoint CPoint9(CurveType::STARK);
    EXPECT_TRUE(CPoint9.IsValid());
    EXPECT_TRUE(CPoint9.IsInfinity());
    std::cout << "CPoint9.Inspect(): " << CPoint9.Inspect() << std::endl;
#endif // ENABLE_STARK
}

void testPointCoordinate(BN bn_x, BN bn_y, CurveType cType) {
    CurvePoint CPoint0;
    CurvePoint CPoint1;
    EXPECT_TRUE(CPoint1.PointFromXY(bn_x, bn_y, cType));
    EXPECT_TRUE(CPoint1.x() == bn_x);
    EXPECT_TRUE(CPoint1.y() == bn_y);
    CPoint1 = CPoint0;
    EXPECT_TRUE(CPoint1.PointFromX(bn_x, bn_y.IsOdd(), cType));
    EXPECT_TRUE(CPoint1.x() == bn_x);
    EXPECT_TRUE(CPoint1.y() == bn_y);
    if(cType == CurveType::ED25519) {
        CPoint1 = CPoint0;
        EXPECT_TRUE(CPoint1.PointFromY(bn_y, bn_x.IsOdd(), cType));
        EXPECT_TRUE(CPoint1.x() == bn_x);
        EXPECT_TRUE(CPoint1.y() == bn_y);
    }
}
TEST(CurvePoint, PointCoordinate) {
    BN bn_x("2706b694c418ff5bbab8e45b66d2910c5c43dc841bcd05b00f5d6057f33eefaa", 16);
    BN bn_y("51d407250de8dc72038ef62f4996ad1a05fdb17210a479b3da233cbee138c247", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);
    bn_x = BN("2242eb559c15239325b62ba1f30f7342fc56a5272de4ebc8f0470db6178e02fb", 16);
    bn_y = BN("78a48a2e24c69eba816ce87eccb0a6f4df5b3d1b00c9424c96887be3cfccc22d", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1);

    bn_x = BN("b6679ce9ab4423d995ba4ccb569fd37455cc939d332f296cfdd1f1699f1bf7df", 16);
    bn_y = BN("2fa22f9ad7fc0dc25743c8713ad990099e66f26b237933dfa967c349ded011fb", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::P256);
    bn_x = BN("1e0cb236e6f2af41be52b08bc1c507c914fac3fcee961435de351e3e10c575c", 16);
    bn_y = BN("dcbc2f8cdb29d8075de8b1172b575b5dcb6ba6339e55ffec116394ca5f2cc712", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::P256);

    bn_x = BN("1a276770f3f04a7bf33ec6726d1b4da3239b3b93b8cd6355b7add64260965bee", 16);
    bn_y = BN("3be31597a8ba0cf943af84d9380a88eeb4691c0cfcfcacf27404418ecee6dfa", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::ED25519);
    bn_x = BN("3cae9b8f387355d18db5e0821552a61f55a3522a1c5bf55e285817bcc051ca8f", 16);
    bn_y = BN("7807f217e163140e825dfdfebd2dbf3463caceca3545e7972b099e0b9bd7bd53", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::ED25519);

#if ENABLE_STARK
    bn_x = BN("234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b", 16);
    bn_y = BN("3b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::STARK));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::STARK);
    bn_x = BN("3909690e1123c80678a7ba0fde0e8447f6f02b3f6b960034d1e93524f8b476", 16);
    bn_y = BN("7122e9063d239d89d4e336753845b76f2b33ca0d7f0c1acd4b9fe974994cc19", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::STARK));
    testPointCoordinate(bn_x, bn_y, safeheron::curve::CurveType::STARK);
#endif // ENABLE_STARK
}


void test_Edwards_PointFromY(const char *x_hex, const char *y_hex, CurveType cType){
    CurvePoint p1, p2;
    BN x(x_hex, 16);
    BN y(y_hex, 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(x, y, cType));
    EXPECT_TRUE(p1.PointFromX(x, y.IsOdd(), cType));
    EXPECT_TRUE(p2.PointFromY(y, x.IsOdd(), cType));
    CurvePoint p0(x, y, cType); // Be careful! "CurvePoint::ValidatePoint" should be invoked firstly.
    EXPECT_TRUE(p0 == p1);
    EXPECT_TRUE(p0 == p2);

    CurvePoint p3;
    EXPECT_TRUE(p3.PointFromXY(x, y, cType));
}

TEST(CurvePoint, MakeCurvePoint)
{
    test_Edwards_PointFromY(
            "602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
            "637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
            CurveType::ED25519);
    test_Edwards_PointFromY(
            "4b87a1147457b111116b878cfc2312de451370ac38fe8690876ef6ac346fd47",
            "405ea0cdd414bda960318b3108769a8928a25b756c372b254c69c78ea2fd81c5",
            CurveType::ED25519);
    test_Edwards_PointFromY(
            "7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
            "ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7",
            CurveType::ED25519);
}

TEST(CurvePoint, Validation) {
    BN bn_x("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    BN bn_y("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    bn_x = BN("2706b694c418ff5bbab8e45b66d2910c5c43dc841bcd05b00f5d6057f33eefaa", 16);
    bn_y = BN("51d407250de8dc72038ef62f4996ad1a05fdb17210a479b3da233cbee138c247", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));
    bn_x = BN("2706b694c418ff5bbab8e45b66d2910c5c43dc841bcd05b00f5d6057f33eefaa", 16);
    bn_y = BN("51d407250de8dc72038ef62f4996ad1a05fdb17210a479b3da233cbee138c248", 16);
    EXPECT_FALSE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::SECP256K1));

    bn_x = BN("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    bn_y = BN("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    bn_x = BN("b6679ce9ab4423d995ba4ccb569fd37455cc939d332f296cfdd1f1699f1bf7df", 16);
    bn_y = BN("2fa22f9ad7fc0dc25743c8713ad990099e66f26b237933dfa967c349ded011fb", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));
    bn_x = BN("b6679ce9ab4423d995ba4ccb569fd37455cc939d332f296cfdd1f1699f1bf7df", 16);
    bn_y = BN("2fa22f9ad7fc0dc25743c8713ad990099e66f26b237933dfa967c349ded011fc", 16);
    EXPECT_FALSE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::P256));

    bn_x = BN("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16);
    bn_y = BN("6666666666666666666666666666666666666666666666666666666666666658", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    bn_x = BN("1a276770f3f04a7bf33ec6726d1b4da3239b3b93b8cd6355b7add64260965bee", 16);
    bn_y = BN("3be31597a8ba0cf943af84d9380a88eeb4691c0cfcfcacf27404418ecee6dfa", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));
    bn_x = BN("1a276770f3f04a7bf33ec6726d1b4da3239b3b93b8cd6355b7add64260965bee", 16);
    bn_y = BN("3be31597a8ba0cf943af84d9380a88eeb4691c0cfcfcacf27404418ecee6dfb", 16);
    EXPECT_FALSE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::ED25519));

#if ENABLE_STARK
    bn_x = BN("40fd002e38ea01a01b2702eb7c643e9decc2894cbf31765922e281939ab542c", 16);
    bn_y = BN("109f720a79e2a41471f054ca885efd90c8cfbbec37991d1b6343991e0a3e740", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::STARK));
    bn_x = BN("2f52066635c139fc2f64eb0bd5e3fd7a705f576854ec4f00aa60361fddb981b", 16);
    bn_y = BN("6d78a24d8a5f97fc600318ce16b3c840315979c3273078ec1a285f217ee6a26", 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::STARK));
    bn_x = BN("6a0767a1fd60d5b9027a35af1b68e57a1c366ebcde2006cdd07af27043ef674", 16);
    bn_y = BN("8606b72c0ca0498b8c1817ed7922d550894c324f5efdfc85a19a1ae382411ca2", 16);
    EXPECT_FALSE(CurvePoint::ValidatePoint(bn_x, bn_y, safeheron::curve::CurveType::STARK));
#endif // ENABLE_STARK
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
