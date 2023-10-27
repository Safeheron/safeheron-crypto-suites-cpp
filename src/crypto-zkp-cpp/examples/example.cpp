#include <google/protobuf/stubs/common.h>
#include <crypto-zkp/zkp.h>
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-zkp/zkp.h"
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

int main(int argc, char **argv) {
    const Curve * curv = GetCurveParam(CurveType::SECP256K1);
    BN r = RandomBNLt(curv->n);
    BN sk = RandomBNLt(curv->n);
    DLogProof proof(CurveType::SECP256K1);
    proof.ProveWithR(sk, r);
    std::cout << (proof.Verify()) << std::endl;

    DLogProof proof2;

    // base64
    std::string base64;
    std::cout << (proof.ToBase64(base64)) << std::endl;
    std::cout << (proof2.FromBase64(base64)) << std::endl;
    std::cout << ((proof.pk_ == proof2.pk_) ) << std::endl;
    std::cout << ((proof.g_r_ == proof2.g_r_) ) << std::endl;
    std::cout << ((proof.res_ == proof2.res_) ) << std::endl;
    std::cout << (proof.Verify()) << std::endl;
    std::cout << (proof2.Verify()) << std::endl;

    //// json string
    std::string jsonStr;
    std::cout << (proof.ToJsonString(jsonStr)) << std::endl;
    std::cout << (proof2.FromJsonString(jsonStr)) << std::endl;
    std::cout << ((proof.pk_ == proof2.pk_) && proof2.Verify()) << std::endl;
    return 0;
}
