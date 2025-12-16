#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-paillier/pail.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::pail::PailPubKey;
using safeheron::pail::PailPrivKey;
using namespace safeheron::zkp;
using namespace safeheron::rand;

TEST(ZKP, PDLProof_V2)
{
    PailPubKey pail_pub;
    PailPrivKey pail_priv;
    CreateKeyPair2048(pail_priv, pail_pub);

    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN x = RandomBNLt(curv->n);
    CurvePoint Q = curv->g * x;

    BN r = RandomBNLtCoPrime(pail_pub.n());
    BN c = pail_pub.EncryptWithR(x, r);

    safeheron::zkp::pdl::PDLStatement statement(c, Q, pail_pub);
    safeheron::zkp::pdl::PDLWitness witness(x, r, pail_priv);

    safeheron::zkp::pdl::PDLProver_V2 prover;
    safeheron::zkp::pdl::PDLVerifier_V2 verifier;

    bool ok = true;
    ok = verifier.Init(statement);
    EXPECT_TRUE(ok);
    ok = prover.Init(statement, witness);
    EXPECT_TRUE(ok);

    // Process:
    // V: message1(c1, c2) => P
    // P: message2(commit(Q)) => V
    // V: message3(a, b) => P
    // P: message4( decommit(Q) ) => V
    // V: Accept
    safeheron::zkp::pdl::PDLVMessage1 v_message1;
    ok = verifier.Step1(v_message1);
    EXPECT_TRUE(ok);
    safeheron::zkp::pdl::PDLPMessage1 p_message1;
    ok = prover.Step1(v_message1, p_message1);
    EXPECT_TRUE(ok);
    safeheron::zkp::pdl::PDLVMessage2 v_message2;
    ok = verifier.Step2(p_message1, v_message2);
    EXPECT_TRUE(ok);
    safeheron::zkp::pdl::PDLPMessage2 p_message2;
    ok = prover.Step2(v_message2,p_message2);
    EXPECT_TRUE(ok);
    ok = verifier.Accept(p_message2);
    EXPECT_TRUE(ok);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
