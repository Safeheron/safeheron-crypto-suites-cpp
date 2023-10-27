#include <cstring>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "crypto-curve/curve.h"
#include "crypto-sss/vsss_secp256k1.h"

using safeheron::bignum::BN;
using namespace safeheron::rand;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using namespace safeheron::sss;
using safeheron::sss::Point;
using safeheron::sss::Polynomial;
using std::vector;


TEST(Secret_Sharing_Scheme, Example1)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    //BN secret = Rand::RandomBNLt(curv->n);
    BN secret("85cf61629bc58c8f03af4e54c69f2a23cc7e967c19a48fb155ba1e08f999b385", 16);
    int threshold = 3;
    vector<Point> shares;
    vector<BN> shareIndexs;
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844344", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844345", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844346", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844347", 16));
    vsss_secp256k1::MakeShares(shares, secret, threshold, shareIndexs);

    for(size_t i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "x: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "y: " << str << std::endl;
    }

    BN recovered_secret;
    vector<Point> new_shares;
    for(int i = 0; i < 3; i++){
        new_shares.push_back(shares[i]);
    }
    vsss_secp256k1::RecoverSecret(recovered_secret, shares);

    EXPECT_TRUE(secret == recovered_secret);

    vsss_secp256k1::RecoverSecret(recovered_secret, new_shares);

    EXPECT_TRUE(secret == recovered_secret);

    // GetLArray
    vector<BN> lArr;
    vector<BN> xArr;
    for(int i = 0; i < 4; i++){
        xArr.push_back(shares[i].x);
    }
    Polynomial::GetLArray(lArr, BN::ZERO, xArr, curv->n);
    recovered_secret = BN::ZERO;
    for(int i = 0; i < 4; i++){
        recovered_secret = ( recovered_secret + lArr[i] * shares[i].y ) % curv->n;
    }
    EXPECT_TRUE(secret == recovered_secret);

}

TEST(Secret_Sharing_Scheme, Example2)
{
    BN secret("85cf61629bc58c8f03af4e54c69f2a23cc7e967c19a48fb155ba1e08f999b385", 16);
    int threshold = 2;
    vector<CurvePoint> cmts;
    vector<Point> shares;
    vector<BN> shareIndexs;
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844344", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844345", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844346", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844347", 16));
    vsss_secp256k1::MakeSharesWithCommits(shares, cmts, secret, threshold, shareIndexs);

    for(size_t i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "x: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "y: " << str << std::endl;
        EXPECT_TRUE(vsss_secp256k1::VerifyShare(cmts, shares[i].x, shares[i].y));
    }

    BN recovered_secret;
    vsss_secp256k1::RecoverSecret(recovered_secret, shares);

    EXPECT_TRUE(secret == recovered_secret);
}

TEST(Secret_Sharing_Scheme, Example3)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    //BN secret = Rand::RandomBNLt(curv->n);
    BN secret("85cf61629bc58c8f03af4e54c69f2a23cc7e967c19a48fb155ba1e08f999b385", 16);
    int threshold = 3;
    vector<CurvePoint> cmts;
    vector<Point> shares;
    vector<BN> shareIndexs;
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844344", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844345", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844346", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844347", 16));
    vector<BN> coeArray;
    coeArray.push_back(BN("3d850101adaa64487171f1c315b732574e98d93ba37166f22a6b128378dc05cc", 16));
    coeArray.push_back(BN("b7720173898dca45bb97b04dbde5ff79a3647f2d2e0c5c4c0fb81b9afa7f9a44", 16));
    vsss_secp256k1::MakeSharesWithCommitsAndCoes(shares, cmts, secret, threshold, shareIndexs,coeArray);

    for(size_t i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "x: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "y: " << str << std::endl;
        EXPECT_TRUE(vsss_secp256k1::VerifyShare(cmts, shares[i].x, shares[i].y));
    }

    BN recovered_secret;
    vsss_secp256k1::RecoverSecret(recovered_secret, shares);

    EXPECT_TRUE(secret == recovered_secret);
}

TEST(Secret_Sharing_Scheme, Example4)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN secret = safeheron::rand::RandomBNLt(curv->n);
    int threshold = 3;
    vector<CurvePoint> cmts;
    vector<Point> shares;
    vector<BN> shareIndexs;
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844344", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844345", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844346", 16));
    shareIndexs.push_back(BN("112151915674366125816987068530776935594844347", 16));
    vsss_secp256k1::MakeSharesWithCommits(shares, cmts, secret, threshold, shareIndexs);

    for(size_t i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "x: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "y: " << str << std::endl;
        EXPECT_TRUE(vsss_secp256k1::VerifyShare(cmts, shares[i].x, shares[i].y));
    }

    BN recovered_secret;
    vsss_secp256k1::RecoverSecret(recovered_secret, shares);

    EXPECT_TRUE(secret == recovered_secret);
}

TEST(Secret_Sharing_Scheme, Example5)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN secret = safeheron::rand::RandomBNLt(curv->n);
    int threshold = 3;
    int num = 4;
    vector<CurvePoint> cmts;
    vector<Point> shares;
    vsss_secp256k1::MakeSharesWithCommits(shares, cmts, secret, threshold, num);

    for(size_t i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "x: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "y: " << str << std::endl;
        EXPECT_TRUE(vsss_secp256k1::VerifyShare(cmts, shares[i].x, shares[i].y));
    }

    BN recovered_secret;
    vsss_secp256k1::RecoverSecret(recovered_secret, shares);
    EXPECT_TRUE(secret == recovered_secret);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
