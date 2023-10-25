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
#include "CTimer.h"

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

TEST(ZKP, TwoDLNProof)
{
    /*
    int PRIME_BITS = 1024 ;
    BN P = RandomSafePrime(PRIME_BITS);
    BN Q = RandomSafePrime(PRIME_BITS);
    BN N_tilde = P * Q;

    BN p = (P-1)/2;
    BN q = (Q-1)/2;
    BN pq = p * q;
    BN f = RandomBNLtGcd(N_tilde);
    BN alpha = RandomBNLtGcd(N_tilde);
    BN beta = alpha.InvM(pq);

    BN h1 = ( f * f ) % N_tilde;
    BN h2 = h1.PowM(alpha, N_tilde);
     */

    BN N_tilde;
    BN h1;
    BN h2;
    BN p;
    BN q;
    BN alpha;
    BN beta;
    dln_proof::GenerateN_tilde(N_tilde, h1, h2, p, q, alpha, beta);

    CTimer t1("dln.prove");
    dln_proof::TwoDLNProof two_dln_proof_1;
    two_dln_proof_1.Prove(N_tilde, h1, h2, p, q , alpha, beta);
    t1.End();

    CTimer t2("two_dln.verify");
    ASSERT_TRUE(two_dln_proof_1.Verify(N_tilde, h1, h2));

    string jsonStr;
    EXPECT_TRUE(two_dln_proof_1.ToJsonString(jsonStr));
    std::cout << "length(two_dln_proof) = " << jsonStr.length() << std::endl;
    t2.End();

    CTimer t3("two_dln2.prove");
    dln_proof::TwoDLNProof two_dln_proof_2;
    two_dln_proof_2.Prove(N_tilde, h1, h2, p, q , alpha, beta);
    t3.End();

    CTimer t4("two_dln2.verify");
    ASSERT_TRUE(two_dln_proof_2.Verify(N_tilde, h1, h2));

    EXPECT_TRUE(two_dln_proof_2.ToJsonString(jsonStr));
    std::cout << "length(two_dln_proof) = " << jsonStr.length() << std::endl;

    dln_proof::RingPedersenParamPub rpp_pub;
    dln_proof::RingPedersenParamPriv rpp_priv;
    rpp_pub.N_tilde_ = N_tilde;
    rpp_pub.h1_ = h1;
    rpp_pub.h2_ = h2;
    rpp_priv.p_ = p;
    rpp_priv.q_ = q;
    rpp_priv.alpha_ = alpha;
    rpp_priv.beta_ = beta;

    std::string base64;
    dln_proof::RingPedersenParamPub rpp_pub_2;
    dln_proof::RingPedersenParamPriv rpp_priv_2;
    rpp_pub.ToBase64(base64);
    EXPECT_TRUE(rpp_pub_2.FromBase64(base64));
    rpp_priv.ToBase64(base64);
    EXPECT_TRUE(rpp_priv_2.FromBase64(base64));
    EXPECT_TRUE(rpp_pub_2.N_tilde_ == rpp_pub.N_tilde_);
    EXPECT_TRUE(rpp_pub_2.h1_ == rpp_pub.h1_);
    EXPECT_TRUE(rpp_pub_2.h2_ == rpp_pub.h2_);
    EXPECT_TRUE(rpp_priv_2.p_ == rpp_priv.p_);
    EXPECT_TRUE(rpp_priv_2.q_ == rpp_priv.q_);
    EXPECT_TRUE(rpp_priv_2.alpha_ == rpp_priv.alpha_);
    EXPECT_TRUE(rpp_priv_2.beta_ == rpp_priv.beta_);

}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
