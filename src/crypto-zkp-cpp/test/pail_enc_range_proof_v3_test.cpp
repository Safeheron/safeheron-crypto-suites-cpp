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

TEST(ZKP, PailEncRangeProof_V3)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    std::string n_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794611";
    std::string g_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794612";
    std::string n_tilde_hex = "C11A2F1A0EA592008BAFCAE756038DE028BA195E73B60F773F7399B4B94E26F8F90C488DEEA7ADB6910BCBCA8BA558E527B67B0B098420D4282411863B3FF39049C420CEB61D4C3683D2264957E583066F9C08C71E7A2A9E8E628E7853C962C4240E2E6FDB1F0F547A33EF0C31BD2B9739E0191AAF948AADE86519CD01A7B944A37C7150DF78A6E6FF4E5B8598F06334374BA068316C73484A07C2A0DF96DFE25931D0C67CE3A8B0E14635F0B34C1937F376EAB077281553F9F81E563DE7111136D95C8A5F9B87D91681AB412A8B62409CD2A2C3386E9B3E2FA3A7B7BE75368415315C1F905B7F38F4ED6758AD88563C41F28B717C7C13573062E6A6D4AA2A8D";
    PailPubKey pail_pub = CreatePailPubKey(n_hex, g_hex);

    // Completeness Range: [0, l]
    // Soundness Range: [l, 2l]
    BN l = curv->n / 3;
    BN double_l = l * 2;

    // Witness
    // Completeness: [0, l]
    BN x = RandomBNLt(l );
    BN r = RandomBNLtCoPrime(pail_pub.n());
    pail::PailEncRangeWitness_V3 witness(x, r);

    // Statement
    BN c = pail_pub.EncryptWithR(x, r);
    pail::PailEncRangeStatement_V3 statement(c, pail_pub, l);

    // Prove
    pail::PailEncRangeProof_V3 proof;
    proof.Prove(statement, witness);

    // Verify
    EXPECT_TRUE(proof.Verify(statement));

    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    std::cout << "PailEncRangeProof_V3 : " << jsonStr << std::endl;

    // base64
    pail::PailEncRangeProof_V3 proof2;
    std::string base64;
    EXPECT_TRUE(proof.ToBase64(base64));
    EXPECT_TRUE(proof2.FromBase64(base64));
    EXPECT_TRUE(proof2.Verify(statement));

    //// json string
    //std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE(proof2.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.Verify(statement));
}

BN SampleRange(const BN &min, const BN &max){
    while(true){
        BN ret = RandomBNLt(max);
        if(ret >= min) return ret;
    }
}

// Range[~, -l]
TEST(ZKP, PailEncRangeProof_V3Failed_Range__Minus_l)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    std::string n_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794611";
    std::string g_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794612";
    std::string n_tilde_hex = "C11A2F1A0EA592008BAFCAE756038DE028BA195E73B60F773F7399B4B94E26F8F90C488DEEA7ADB6910BCBCA8BA558E527B67B0B098420D4282411863B3FF39049C420CEB61D4C3683D2264957E583066F9C08C71E7A2A9E8E628E7853C962C4240E2E6FDB1F0F547A33EF0C31BD2B9739E0191AAF948AADE86519CD01A7B944A37C7150DF78A6E6FF4E5B8598F06334374BA068316C73484A07C2A0DF96DFE25931D0C67CE3A8B0E14635F0B34C1937F376EAB077281553F9F81E563DE7111136D95C8A5F9B87D91681AB412A8B62409CD2A2C3386E9B3E2FA3A7B7BE75368415315C1F905B7F38F4ED6758AD88563C41F28B717C7C13573062E6A6D4AA2A8D";
    PailPubKey pail_pub = CreatePailPubKey(n_hex, g_hex);

    // Range: [l, 2l]
    BN l = curv->n / 3;
    BN double_l = l * 2;

    // Witness
    BN x = SampleRange(l, curv->n);
    x = BN::ZERO - x;
    BN r = RandomBNLtCoPrime(pail_pub.n());
    pail::PailEncRangeWitness_V3 witness(x, r);

    // Statement
    BN c = pail_pub.EncryptWithR(x, r);
    pail::PailEncRangeStatement_V3 statement(c, pail_pub, l);

    // Prove
    pail::PailEncRangeProof_V3 proof;
    proof.Prove(statement, witness);

    // Verify
    EXPECT_FALSE(proof.Verify(statement));
}

// Range[2l, ~]
TEST(ZKP, PailEncRangeProof_V3Failed_Range_2l_)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    std::string n_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794611";
    std::string g_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794612";
    std::string n_tilde_hex = "C11A2F1A0EA592008BAFCAE756038DE028BA195E73B60F773F7399B4B94E26F8F90C488DEEA7ADB6910BCBCA8BA558E527B67B0B098420D4282411863B3FF39049C420CEB61D4C3683D2264957E583066F9C08C71E7A2A9E8E628E7853C962C4240E2E6FDB1F0F547A33EF0C31BD2B9739E0191AAF948AADE86519CD01A7B944A37C7150DF78A6E6FF4E5B8598F06334374BA068316C73484A07C2A0DF96DFE25931D0C67CE3A8B0E14635F0B34C1937F376EAB077281553F9F81E563DE7111136D95C8A5F9B87D91681AB412A8B62409CD2A2C3386E9B3E2FA3A7B7BE75368415315C1F905B7F38F4ED6758AD88563C41F28B717C7C13573062E6A6D4AA2A8D";
    PailPubKey pail_pub = CreatePailPubKey(n_hex, g_hex);

    // Range: [l, 2l]
    BN l = curv->n / 3;
    BN double_l = l * 2;

    // Failed: Range (2l, q)
    // Witness
    BN x = SampleRange(double_l, curv->n);
    BN r = RandomBNLtCoPrime(pail_pub.n());
    pail::PailEncRangeWitness_V3 witness(x, r);

    // Statement
    BN c = pail_pub.EncryptWithR(x, r);
    pail::PailEncRangeStatement_V3 statement(c, pail_pub, l);

    CTimer timer_prove("time_cost_of_prove");
    // Prove
    pail::PailEncRangeProof_V3 proof;
    proof.Prove(statement, witness);
    timer_prove.End();

    CTimer timer_verify("time_cost_of_verify");
    // Verify
    EXPECT_FALSE(proof.Verify(statement));
    timer_verify.End();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
