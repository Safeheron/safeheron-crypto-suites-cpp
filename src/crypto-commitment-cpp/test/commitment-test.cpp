#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-encode/hex.h"
#include "crypto-curve/curve.h"
#include "crypto-commitment/commitment.h"
#include "crypto-bn/rand.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::commitment::KgdCurvePoint;
using safeheron::commitment::KgdNumber;
using safeheron::commitment::Com256;
using safeheron::commitment::Com512;


TEST(Commitment, Number)
{
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN r = safeheron::rand::RandomBNLt(curv->n);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN blind_factor = safeheron::rand::RandomBNLt(curv->n);
    BN com_num = safeheron::commitment::CreateComWithBlind(msg, blind_factor);
    std::string str;
    com_num.ToHexStr(str);
    std::cout << "commitment(number) :" << str << std::endl;
}

TEST(Commitment, CurvePoint)
{
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN r = safeheron::rand::RandomBNLt(curv->n);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN blind_factor = safeheron::rand::RandomBNLt(curv->n);
    CurvePoint point = curv->g * r;

    std::string str;
    BN com_point = safeheron::commitment::CreateComWithBlind(point, blind_factor);
    com_point.ToHexStr(str);
    std::cout << "commitment(point) :" << str << std::endl;
}

TEST(Commitment, CurvePoints)
{
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN r0 = safeheron::rand::RandomBNLt(curv->n);
    BN r1 = safeheron::rand::RandomBNLt(curv->n);
    BN r2 = safeheron::rand::RandomBNLt(curv->n);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN blind_factor = safeheron::rand::RandomBNLt(curv->n);
    CurvePoint point0 = curv->g * r0;
    CurvePoint point1 = curv->g * r1;
    CurvePoint point2 = curv->g * r2;
    std::vector<CurvePoint> points;
    points.push_back(point0);
    points.push_back(point1);
    points.push_back(point2);

    std::string str;
    BN com_point = safeheron::commitment::CreateComWithBlind(points, blind_factor);
    com_point.ToHexStr(str);
    std::cout << "commitment(point) :" << str << std::endl;
}

TEST(Com256, Com256)
{
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN r0 = safeheron::rand::RandomBNLt(curv->n);
    BN r1 = safeheron::rand::RandomBNLt(curv->n);
    BN r2 = safeheron::rand::RandomBNLt(curv->n);
    CurvePoint point0 = curv->g * r0;
    CurvePoint point1 = curv->g * r1;
    CurvePoint point2 = curv->g * r2;

    uint8_t buf[32];
    safeheron::rand::RandomBytes(buf, 32);
    std::string blind_factor((char*)buf, 32);

    Com256 com;
    std::string com_value;
    com.CommitBN(msg);
    com.CommitBN(r0);
    com.CommitBN(r1);
    com.CommitBN(r2);
    com.CommitCurvePoint(point0);
    com.CommitCurvePoint(point1);
    com.CommitCurvePoint(point2);
    com.Finalize(blind_factor, com_value);

    std::cout << "commitment(Com256) :" << safeheron::encode::hex::EncodeToHex(com_value) << std::endl;
}

TEST(Com512, Com512)
{
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN r0 = safeheron::rand::RandomBNLt(curv->n);
    BN r1 = safeheron::rand::RandomBNLt(curv->n);
    BN r2 = safeheron::rand::RandomBNLt(curv->n);
    CurvePoint point0 = curv->g * r0;
    CurvePoint point1 = curv->g * r1;
    CurvePoint point2 = curv->g * r2;

    uint8_t buf[32];
    safeheron::rand::RandomBytes(buf, 32);
    std::string blind_factor((char*)buf, 32);

    Com512 com;
    std::string com_value;
    com.CommitBN(msg);
    com.CommitBN(r0);
    com.CommitBN(r1);
    com.CommitBN(r2);
    com.CommitCurvePoint(point0);
    com.CommitCurvePoint(point1);
    com.CommitCurvePoint(point2);
    com.Finalize(blind_factor, com_value);

    std::cout << "commitment(Com512) :" << safeheron::encode::hex::EncodeToHex(com_value) << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
