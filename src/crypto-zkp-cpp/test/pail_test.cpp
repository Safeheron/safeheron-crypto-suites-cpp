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

TEST(ZKP, PailNProof)
{
    PailPubKey pail_pub;
    PailPrivKey pail_priv;
    CreateKeyPair2048(pail_priv, pail_pub);

    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN r = RandomBNLt(curv->n);
    CurvePoint point = curv->g * r;
    BN index = RandomBNLtGcd(curv->n);

    CTimer timer("prove" );
    PailProof proof;
    proof.Prove(pail_priv, index, point.x(), point.y());
    timer.End();
    timer.Reset("verify" );
    ASSERT_TRUE(proof.Verify(pail_pub, index, point.x(), point.y()));
    timer.End();

    //// json string
    PailProof proof2;
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    std::cout << "length(pailN) = " << jsonStr.length() << std::endl;
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE(proof2.Verify(pail_pub, index, point.x(), point.y()));
    for(size_t i = 0; i < proof.y_N_arr_.size(); ++i){
        EXPECT_TRUE(proof.y_N_arr_[i] == proof2.y_N_arr_[i]);
    }

    // Failed
    proof2.y_N_arr_[2] = BN();
    EXPECT_FALSE(proof2.Verify(pail_pub, index, point.x(), point.y()));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
