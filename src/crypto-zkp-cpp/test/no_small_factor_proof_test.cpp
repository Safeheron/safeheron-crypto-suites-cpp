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
using safeheron::zkp::no_small_factor_proof::NoSmallFactorWitness;
using safeheron::zkp::no_small_factor_proof::NoSmallFactorProof;
using safeheron::zkp::no_small_factor_proof::NoSmallFactorStatement;
using safeheron::zkp::no_small_factor_proof::NoSmallFactorSetUp;
using namespace safeheron::zkp;
using namespace safeheron::encode;
using namespace safeheron::rand;

TEST(ZKP, NoSmallFactorProof)
{
    std::string n_tilde_hex = "C11A2F1A0EA592008BAFCAE756038DE028BA195E73B60F773F7399B4B94E26F8F90C488DEEA7ADB6910BCBCA8BA558E527B67B0B098420D4282411863B3FF39049C420CEB61D4C3683D2264957E583066F9C08C71E7A2A9E8E628E7853C962C4240E2E6FDB1F0F547A33EF0C31BD2B9739E0191AAF948AADE86519CD01A7B944A37C7150DF78A6E6FF4E5B8598F06334374BA068316C73484A07C2A0DF96DFE25931D0C67CE3A8B0E14635F0B34C1937F376EAB077281553F9F81E563DE7111136D95C8A5F9B87D91681AB412A8B62409CD2A2C3386E9B3E2FA3A7B7BE75368415315C1F905B7F38F4ED6758AD88563C41F28B717C7C13573062E6A6D4AA2A8D";
    BN N_tilde = BN::FromHexStr(n_tilde_hex);
    BN h1 = RandomBNLtGcd(N_tilde);
    h1 = ( h1 * h1 ) % N_tilde;
    BN h2 = RandomBNLtGcd(N_tilde);
    h2 = ( h2 * h2 ) % N_tilde;

    BN P = RandomSafePrimeStrict(1024);
    BN Q = RandomSafePrimeStrict(1024);
    BN N = P * Q;

    CTimer timer("prove" );
    NoSmallFactorSetUp set_up(N_tilde, h1, h2);
    NoSmallFactorStatement statement(N, 256, 512);
    NoSmallFactorWitness witness(P, Q);
    NoSmallFactorProof proof;
    proof.Prove(set_up, statement, witness);
    timer.End();
    timer.Reset("verify" );
    ASSERT_TRUE(proof.Verify(set_up, statement));
    timer.End();

    //// json string
    NoSmallFactorProof proof2;
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    std::cout << "length(pailN) = " << jsonStr.length() << std::endl;
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE(proof2.Verify(set_up, statement));

    //// json string
    NoSmallFactorProof proof3;
    std::string base64;
    EXPECT_TRUE(proof.ToBase64(base64));
    EXPECT_TRUE(proof3.FromBase64(base64));
    EXPECT_TRUE(proof3.Verify(set_up, statement));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
