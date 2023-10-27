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
using safeheron::zkp::dlog::DLogProof;
using safeheron::zkp::dlog::DLogProof;
using safeheron::zkp::heg::HegProof;
using safeheron::zkp::pail::PailProof;
using safeheron::pail::PailPubKey;
using safeheron::pail::PailPrivKey;
using safeheron::pail::CreatePailPubKey;
using namespace safeheron::zkp;
using namespace safeheron::encode;
using namespace safeheron::rand;


TEST(ZKP, DLogProof)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN r = RandomBNLt(curv->n);
    BN sk = RandomBNLt(curv->n);
    DLogProof proof(CurveType::SECP256K1);
    proof.ProveWithR(sk, r);
    EXPECT_TRUE(proof.Verify());

    DLogProof proof2;

    // base64
    std::string base64;
    EXPECT_TRUE(proof.ToBase64(base64));
    EXPECT_TRUE(proof2.FromBase64(base64));
    EXPECT_TRUE((proof.pk_ == proof2.pk_) );
    EXPECT_TRUE((proof.g_r_ == proof2.g_r_) );
    EXPECT_TRUE((proof.res_ == proof2.res_) );
    EXPECT_TRUE(proof.Verify());
    EXPECT_TRUE(proof2.Verify());

    //// json string
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE((proof.pk_ == proof2.pk_) && proof2.Verify());
}

TEST(ZKP, DLogProofEx)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN r = RandomBNLt(curv->n);
    BN sk = RandomBNLt(curv->n);
    DLogProof proof;
    proof.ProveWithREx(sk, r, CurveType::SECP256K1);
    EXPECT_TRUE(proof.Verify());

    DLogProof proof2;

    // base64
    std::string base64;
    EXPECT_TRUE(proof.ToBase64(base64));
    EXPECT_TRUE(proof2.FromBase64(base64));
    EXPECT_TRUE((proof.pk_ == proof2.pk_) );
    EXPECT_TRUE((proof.g_r_ == proof2.g_r_) );
    EXPECT_TRUE((proof.res_ == proof2.res_) );
    EXPECT_TRUE(proof.Verify());
    EXPECT_TRUE(proof2.Verify());

    //// json string
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE((proof.pk_ == proof2.pk_) && proof2.Verify());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
