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

TEST(ZKP, PDLProof)
{
    PailPubKey pail_pub;
    PailPrivKey pail_priv;
    CreateKeyPair2048(pail_priv, pail_pub);

    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN x = RandomBNLt(curv->n);
    CurvePoint Q = curv->g * x;

    BN c = pail_pub.Encrypt(x);

    safeheron::bignum::BN c1;
    safeheron::bignum::BN c2;
    safeheron::bignum::BN commit_Q;
    safeheron::bignum::BN a;
    safeheron::bignum::BN b;
    safeheron::bignum::BN blind_a_b;
    safeheron::curve::CurvePoint Q_hat;
    safeheron::bignum::BN blind_Q_hat;

    safeheron::zkp::pdl::PDLProver prover(c, Q, pail_pub, pail_priv, x);
    safeheron::zkp::pdl::PDLVerifier verifier(c, Q, pail_pub);

    // Process:
    // V: message1(c1, c2) => P
    // P: message2(commit(Q)) => V
    // V: message3(a, b) => P
    // P: message4( decommit(Q) ) => V
    // V: Accept
    bool ok = true;
    ok = verifier.Step1(c1, c2);
    EXPECT_TRUE(ok);
    ok = prover.Step1(c1, c2, commit_Q);
    EXPECT_TRUE(ok);
    ok = verifier.Step2(commit_Q, a, b, blind_a_b);
    EXPECT_TRUE(ok);
    ok = prover.Step2(a, b, blind_a_b, Q_hat, blind_Q_hat);
    EXPECT_TRUE(ok);
    ok = verifier.Accept(Q_hat, blind_Q_hat);
    EXPECT_TRUE(ok);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
