#include "pdl_proof.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-paillier/pail.h"
#include "crypto-commitment/commitment.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::hash::CSHA256;
using safeheron::pail::PailPubKey;
using safeheron::pail::PailPrivKey;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;
using namespace safeheron::rand;

namespace safeheron{
namespace zkp {
namespace pdl {

bool PDLVerifier::Step1(safeheron::bignum::BN &c1, safeheron::bignum::BN &c2){
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(Q_.GetCurveType());
    // Sample a, b in [0, q]
    a_ = RandomBNLt(curv->n);
    b_ = RandomBNLt(curv->n);

    // c' = Enc(pail_pub, a*x + b)
    c1_ = pail_pub_.HomomorphicMulPlain(c_, a_);
    c1_ = pail_pub_.HomomorphicAddPlain(c1_, b_);

    // c'' = commit(a, b)
    std::vector<BN> n_arr;
    n_arr.push_back(a_);
    n_arr.push_back(b_);
    blind_a_b_ = RandomBN(256);
    c2_ = safeheron::commitment::CreateComWithBlind(n_arr, blind_a_b_);

    expected_Q_hat_ = Q_ * a_ + curv->g * b_;

    c1 = c1_;
    c2 = c2_;

    return true;
}

bool PDLVerifier::Step2(const safeheron::bignum::BN &commit_Q_hat, safeheron::bignum::BN &a, safeheron::bignum::BN &b, safeheron::bignum::BN &blind_a_b){
    a = a_;
    b = b_;
    blind_a_b = blind_a_b_;
    commit_Q_hat_ = commit_Q_hat;
    return true;
}

bool PDLVerifier::Accept(const safeheron::curve::CurvePoint &Q_hat, const safeheron::bignum::BN &blind_Q_hat) const {
    BN commit_Q_hat = safeheron::commitment::CreateComWithBlind(Q_hat, blind_Q_hat);
    return (commit_Q_hat == commit_Q_hat_) && (expected_Q_hat_ == Q_hat);
}

bool PDLProver::Step1(const safeheron::bignum::BN &c1, const safeheron::bignum::BN &c2, safeheron::bignum::BN &commit_Q_hat){
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(Q_.GetCurveType());
    c2_ = c2;
    alpha_ = pail_priv_.Decrypt(c1);
    Q_hat_ = curv->g * alpha_;
    blind_Q_hat_ = RandomBN(256);
    commit_Q_hat = safeheron::commitment::CreateComWithBlind(Q_hat_, blind_Q_hat_);

    return true;
}

bool PDLProver::Step2(const safeheron::bignum::BN &a, const safeheron::bignum::BN &b, const safeheron::bignum::BN &blind_a_b,
                      safeheron::curve::CurvePoint &Q_hat, safeheron::bignum::BN &blind_Q_hat){
    bool ok = true;
    std::vector<BN> n_arr;
    n_arr.push_back(a);
    n_arr.push_back(b);
    BN expected_c2 = safeheron::commitment::CreateComWithBlind(n_arr, blind_a_b);
    ok = c2_ == expected_c2;
    if( !ok ) return false;

    BN expected_alpha = x_ * a + b;
    ok = alpha_ == expected_alpha;
    if( !ok ) return false;

    Q_hat = Q_hat_;
    blind_Q_hat = blind_Q_hat_;

    return true;
}


}
}
}
