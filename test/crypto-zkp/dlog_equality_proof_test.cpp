#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "crypto-suites/crypto-zkp/zkp.h"
#include "gtest/gtest.h"
#include "crypto-suites/crypto-hash/sha256.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/exception/located_exception.h"

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

TEST(ZKP, Pail_ENC_Range_Proof_3)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    const CurvePoint &g = curv->g;
    BN x = RandomBNLt(curv->n);
    BN y = RandomBNLt(curv->n);
    BN r = RandomBNLt(curv->n);

    CurvePoint h = g * r;
    CurvePoint X = g * x;
    CurvePoint Y = h * x;

    dlog_equality::DlogEqualityStatement statement(g, h, X, Y, curv->n);

    dlog_equality::DlogEqualityProof proof;
    proof.Prove(statement, x);
    ASSERT_TRUE(proof.Verify(statement));

    std::string base64;
    proof.ToBase64(base64);
    dlog_equality::DlogEqualityProof proof2;
    ASSERT_TRUE(proof2.FromBase64(base64));
    ASSERT_TRUE(proof2.Verify(statement));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
