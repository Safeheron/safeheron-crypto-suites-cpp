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

TEST(ZKP, PailBlumModulusProof)
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

    CTimer timer("prove" );
    safeheron::zkp::pail::PailBlumModulusProof proof;
    ASSERT_TRUE(proof.Prove(N_tilde, P, Q));
    timer.End();
    timer.Reset("verify");
    ASSERT_TRUE(proof.Verify(N_tilde));
    timer.End();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
