#include <cstring>
#include <google/protobuf/stubs/common.h>
#include <crypto-zkp/zkp.h>
#include "gtest/gtest.h"
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-zkp/zkp.h"
#include "crypto-paillier/pail.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::GetCurveParam;
using safeheron::hash::CSHA256;
using google::protobuf::util::Status;
using safeheron::zkp::dlog::DLogProof_V3;
using namespace safeheron::zkp;
using namespace safeheron::encode;
using namespace safeheron::rand;


TEST(ZKP, DLogProof_V3)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN alpha = RandomBNLt(curv->n);
    BN r = RandomBNLt(curv->n);
    BN x = RandomBNLt(curv->n);
    CurvePoint G = curv->g * r;
    CurvePoint X = G * x;
    DLogProof_V3 proof;
    proof.ProveWithR(x, G, curv->n, alpha);
    EXPECT_TRUE(proof.Verify(X, G, curv->n));

    DLogProof_V3 proof2;

    // base64
    std::string base64;
    EXPECT_TRUE(proof.ToBase64(base64));
    EXPECT_TRUE(proof2.FromBase64(base64));
    EXPECT_TRUE((proof.A_ == proof2.A_) );
    EXPECT_TRUE((proof.z_ == proof2.z_) );
    EXPECT_TRUE(proof.Verify(X, G, curv->n));
    EXPECT_TRUE(proof2.Verify(X, G, curv->n));

    //// json string
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE(proof2.Verify(X, G, curv->n));
}

TEST(ZKP, DLogProof_V3_WithSalt)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN alpha = RandomBNLt(curv->n);
    BN r = RandomBNLt(curv->n);
    BN x = RandomBNLt(curv->n);
    CurvePoint G = curv->g * r;
    CurvePoint X = G * x;
    DLogProof_V3 proof;
    proof.SetSalt("sault");
    proof.ProveWithR(x, G, curv->n, alpha);
    EXPECT_TRUE(proof.Verify(X, G, curv->n));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
