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

TEST(ZKP, HegProof)
{
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    // Witness
    BN r = RandomBNLt(curv->n);
    BN x = RandomBNLt(curv->n);
    heg::HomoElGamalWitness witness(r, x);

    // Statement
    BN h = RandomBNLt(curv->n);
    CurvePoint H = curv->g * h;
    BN y = RandomBNLt(curv->n);
    CurvePoint Y = curv->g * y;
    CurvePoint D = H * x + Y * r;
    CurvePoint E = curv->g * r;
    heg::HomoElGamalStatement statement(curv->g, H, Y, D, E);

    // Prove
    heg::HegProof proof;
    proof.Prove(statement, witness);

    // Verify
    EXPECT_TRUE(proof.Verify(statement));

    // base64
    heg::HegProof proof2;
    std::string base64;
    EXPECT_TRUE(proof.ToBase64(base64));
    EXPECT_TRUE(proof2.FromBase64(base64));
    EXPECT_TRUE((proof.T_ == proof2.T_) );
    EXPECT_TRUE((proof.A3_ == proof2.A3_) );
    EXPECT_TRUE((proof.z1_ == proof2.z1_) );
    EXPECT_TRUE((proof.z2_ == proof2.z2_) );
    EXPECT_TRUE(proof.Verify(statement));
    EXPECT_TRUE(proof2.Verify(statement));

    //// json string
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE((proof.T_ == proof2.T_) && proof2.Verify(statement));
}

TEST(ZKP, PailProof)
{
    PailPubKey pail_pub;
    PailPrivKey pail_priv;
    CreateKeyPair2048(pail_priv, pail_pub);

    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN r = RandomBNLt(curv->n);
    CurvePoint point = curv->g * r;
    BN index = RandomBNLtGcd(curv->n);

    PailProof proof;
    proof.Prove(pail_priv, index, point.x(), point.y());
    ASSERT_TRUE(proof.Verify(pail_pub, index, point.x(), point.y()));

    //// json string
    PailProof proof2;
    std::string jsonStr;
    EXPECT_TRUE(proof.ToJsonString(jsonStr));
    EXPECT_TRUE(proof2.FromJsonString(jsonStr));
    EXPECT_TRUE(proof2.Verify(pail_pub, index, point.x(), point.y()));
    for(size_t i = 0; i < proof.y_N_arr_.size(); ++i){
        EXPECT_TRUE(proof.y_N_arr_[i] == proof2.y_N_arr_[i]);
    }

    // Failed
    proof2.y_N_arr_[2] = BN();
    EXPECT_FALSE(proof2.Verify(pail_pub, index, point.x(), point.y()));
}

TEST(ZKP, RangeProof)
{
    BN n11(11);
    BN n5(5);
    BN n3(-3);
    BN n2(-2);
    std::cout << n2.Inspect() <<std::endl;
    std::cout << n5.PowM(n2, n11).Inspect() <<std::endl;
    std::cout << n5.PowM(n3, n11).Inspect() <<std::endl;
    std::cout << n5.PowM(n11 - 1 + n3, n11).Inspect() <<std::endl;
    std::cout << n5.PowM(n3.Neg(), n11).Inspect() <<std::endl;
    std::cout << n5.PowM(n3.Neg(), n11).InvM(n11).Inspect() <<std::endl;
    std::cout << n3.Neg().Inspect() <<std::endl;

    std::string n_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794611";
    std::string g_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794612";
    std::string n_tilde_hex = "C11A2F1A0EA592008BAFCAE756038DE028BA195E73B60F773F7399B4B94E26F8F90C488DEEA7ADB6910BCBCA8BA558E527B67B0B098420D4282411863B3FF39049C420CEB61D4C3683D2264957E583066F9C08C71E7A2A9E8E628E7853C962C4240E2E6FDB1F0F547A33EF0C31BD2B9739E0191AAF948AADE86519CD01A7B944A37C7150DF78A6E6FF4E5B8598F06334374BA068316C73484A07C2A0DF96DFE25931D0C67CE3A8B0E14635F0B34C1937F376EAB077281553F9F81E563DE7111136D95C8A5F9B87D91681AB412A8B62409CD2A2C3386E9B3E2FA3A7B7BE75368415315C1F905B7F38F4ED6758AD88563C41F28B717C7C13573062E6A6D4AA2A8D";
    PailPubKey pail_pub = CreatePailPubKey(n_hex, g_hex);

    BN N_tilde = BN::FromHexStr(n_tilde_hex);

    std::cout << "tag1 " << std::endl;

    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN m = RandomBNLt(curv->n);
    std::cout << "tag2.1 " << std::endl;
    std::cout << "pail_pub: " <<pail_pub.n().Inspect() << std::endl;
    BN r = RandomBNLtGcd(pail_pub.n());
    std::cout << "tag2.2 " << std::endl;
    BN c = pail_pub.EncryptWithR(m, r);
    std::cout << "tag2.3 " << std::endl;

    BN h1 = RandomBNLtGcd(N_tilde);
    h1 = ( h1 * h1 ) % N_tilde;

    BN h2 = RandomBNLtGcd(N_tilde);
    h2 = ( h2 * h2 ) % N_tilde;
    std::cout << "tag3 " << std::endl;

    range_proof::AliceRangeProof range_proof;
    range_proof.Prove(curv->n, pail_pub.n(), pail_pub.g(), N_tilde, h1, h2, c, m , r);
    ASSERT_TRUE(range_proof.Verify(curv->n, pail_pub.n(), pail_pub.g(), N_tilde, h1, h2, c));

    std::string base64;
    range_proof.ToBase64(base64);
    range_proof::AliceRangeProof range_proof2;
    ASSERT_TRUE(range_proof2.FromBase64(base64));
    ASSERT_TRUE(range_proof2.Verify(curv->n, pail_pub.n(), pail_pub.g(), N_tilde, h1, h2, c));


}

TEST(ZKP, DLNProof)
{
    //std::string P_hex = "CDD7E448B1F718AEFFA58F27F8F843115B8C43E787FC8469FD14332D7B226D0253A6693D522D7F1012D77AE33055AA26CCC066AACD2C24BE4DFAE0608F4750118710CE1ADA6AB526AC11B569C9FF0F28BF3491625F676985BBD4E8ACFA3B70B34B52C7F348EA649A4637F86B35CA74201FF020D7201F02905FFF38234A3AB3A3";
    //std::string Q_hex = "D560D3612DF238CDEEEB3FDA37F040B409BC25F4FFA2A8227E6C02523E8EC5B835F0BBBEFA0B5D09B305964156A3EF96BA50CCA35B9D3EA768258EE6CF090F20AED0896F7E9050ABD749FE0052EE9DC6DFC261FCE400F855A9F039CF3599D5AD6762C1A1DE00021B5B88D3FD35A207B738D9F37D52CE049ADEA29180115EB0E3";
    //std::string N_tilde_hex = "AB927BDD2C3C7550583B7408A8AFDEECEB5C4CBB98491B290832AFCF1015A1983097E07B4C8A4EE13D10ECD594457569ADA156CD01CABD54048831A1550DCEB7AC9901F26D8497CED857401391132F19EFB6B9A72FDAFE3A6DA1FA1649C72FA1B4B31902301922C19498C187F520139A3BBFC1E02CE948DEA92A97AB1B52518ABED1C3470DE2DCE6E6895D3EC8BBC50329D0F3EDCA827B9D7928DD173B78BBF2CDE5A43B5F142D8940007DE426C788E71FBFB2ED130724F9C24BCF6015CCDED54091F0D7DF53FC622FFB1C469F8E578A40029F60CF2D5367E104E9CC5E0F30A8E97BEA4835AEFC35B60B614A9DA08D5E4E1F4AE6590A4620EF09564EF6675989";

    //BN P = BN::FromHexStr(P_hex);
    //BN Q = BN::FromHexStr(Q_hex);
    //BN N_tilde = BN::FromHexStr(N_tilde_hex);

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

    dln_proof::DLNProof dln_proof;
    dln_proof.Prove(N_tilde, h1, h2, p, q , alpha);
    ASSERT_TRUE(dln_proof.Verify(N_tilde, h1, h2));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
