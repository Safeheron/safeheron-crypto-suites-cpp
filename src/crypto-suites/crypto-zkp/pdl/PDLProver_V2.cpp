#include "PDLProver_V2.h"

#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/com256.h"
#include "crypto-suites/crypto-paillier/pail_privkey.h"
#include "crypto-suites/crypto-paillier/pail_pubkey.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using namespace safeheron::rand;
using safeheron::commitment::HashCommit256;
using safeheron::pail::PailPrivKey;
using safeheron::pail::PailPubKey;

namespace safeheron{
namespace zkp {
namespace pdl {

bool  PDLProver_V2::Init(const PDLStatement &statement, const PDLWitness &witness) {
    x_ = witness.x_;
    r_ = witness.r_;
    pail_priv_ = witness.pail_priv_;
    c_ = statement.c_;
    Q_ = statement.Q_;
    pail_pub_ = statement.pail_pub_;

    if (c_ != pail_pub_.EncryptWithR(x_, r_)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(Q_.GetCurveType());
    const safeheron::bignum::BN q = curv->n;
    if (!(x_ >= 0 && x_ < q)) return false;

    is_initialized_ = true;
    return true;
}

bool PDLProver_V2::Step1(const PDLVMessage1 &v_message1, PDLPMessage1 &p_message1) {
    if (!is_initialized_) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(Q_.GetCurveType());
    c1_ = v_message1.c1_;
    c2_ = v_message1.c2_;
    alpha_ = pail_priv_.Decrypt(c1_);
    Q_hat_ = curv->g * alpha_;
    blind_Q_hat_ = RandomBytes(32);
    HashCommit256 sha256_com;
    sha256_com.UpdateCurvePoint(Q_hat_);
    p_message1.commit_Q_hat_ = sha256_com.Commit(blind_Q_hat_);
    return true;
}

bool PDLProver_V2::Step2(const PDLVMessage2 &v_message2, PDLPMessage2 &p_message2) {
    bool ok = true;
    HashCommit256 sha256_com;
    sha256_com.UpdateBN(v_message2.a_);
    sha256_com.UpdateBN(v_message2.b_);
    ok = sha256_com.OpenAndVerify(v_message2.blind_a_b_, c2_);
    if(!ok) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(Q_.GetCurveType());
    const safeheron::bignum::BN q = curv->n;

    // alpha = a * (x + q) + b
    BN expected_alpha = (x_ + q) * v_message2.a_ + v_message2.b_;
    ok = alpha_ == expected_alpha;
    if(!ok) return false;

    p_message2.Q_hat_ = Q_hat_;
    p_message2.blind_Q_hat_ = blind_Q_hat_;

    const safeheron::bignum::BN& l = q;
    safeheron::zkp::pail::PailEncRangeStatement_V3 statement(c_, pail_pub_, l);
    safeheron::zkp::pail::PailEncRangeWitness_V3 witness(x_, r_);
    safeheron::zkp::pail::PailEncRangeProof_V3 pail_enc_rang_proof;
    if (!salt_.empty()) pail_enc_rang_proof.SetSalt(salt_);
    pail_enc_rang_proof.Prove(statement, witness);

    p_message2.pail_enc_rang_proof_ = pail_enc_rang_proof;

    return true;
}


}
}
}