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


TEST(ZKP, HegProof_V2)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    // Witness
    BN s = RandomBNLt(curv->n);
    BN l = RandomBNLt(curv->n);
    heg::HEGWitness_V2 witness(s, l);

    // Statement
    // R
    BN r = RandomBNLt(curv->n);
    CurvePoint R = curv->g * r;
    // A
    BN a = RandomBNLt(curv->n);
    CurvePoint A = curv->g * a;
    CurvePoint V = R * s + curv->g * l;
    CurvePoint B = A * l;
    heg::HEGStatement_V2 statement(curv->g, V, R, A, B, curv->n);

    // Prove
    heg::HEGProof_V2 proof;
    proof.Prove(statement, witness);

    // Verify
    EXPECT_TRUE(proof.Verify(statement));

    // base64
    heg::HEGProof_V2 proof2;
    std::string base64;
    EXPECT_TRUE(proof.ToBase64(base64));
    EXPECT_TRUE(proof2.FromBase64(base64));
    EXPECT_TRUE((proof.Alpha_ == proof2.Alpha_) );
    EXPECT_TRUE((proof.Beta_ == proof2.Beta_) );
    EXPECT_TRUE((proof.t_ == proof2.t_) );
    EXPECT_TRUE((proof.u_ == proof2.u_) );
    EXPECT_TRUE(proof.Verify(statement));
    EXPECT_TRUE(proof2.Verify(statement));

    //// json string
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE((proof.Alpha_ == proof2.Alpha_) && proof2.Verify(statement));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
