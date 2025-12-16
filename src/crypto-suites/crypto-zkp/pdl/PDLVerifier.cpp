#include "PDLVerifier.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/com256.h"
#include "crypto-suites/crypto-paillier/pail_pubkey.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::commitment::HashCommit256;
using safeheron::pail::PailPubKey;
using namespace safeheron::rand;

namespace safeheron{
namespace zkp {
namespace pdl {

bool PDLVerifier::Init(const PDLStatement &statement) {
    c_ = statement.c_;
    Q_ = statement.Q_;
    pail_pub_ = statement.pail_pub_;
    is_initialized_ = true;
    return true;
}

bool PDLVerifier::Step1(PDLVMessage1 &v_message1) {
    if (!is_initialized_) return false;
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(Q_.GetCurveType());

    const safeheron::bignum::BN &q = curv->n;
    const safeheron::bignum::BN q2 = q * q;

    // Sample a in [0, q]
    a_ = RandomBNLt(q);
    // Sample b in [0, q^2]
    b_ = RandomBNLt(q2);

    // Compute c1 = Enc(pail_pub, a*x + b)
    safeheron::bignum::BN c1 = pail_pub_.HomomorphicMulPlain(c_, a_);
    safeheron::bignum::BN r = safeheron::rand::RandomBNLtCoPrime(pail_pub_.n());
    c1 = pail_pub_.HomomorphicAdd(c1, pail_pub_.EncryptWithR(b_, r));

    // Compute c2 = commit(a, b)
    HashCommit256 sha256_com;
    sha256_com.UpdateBN(a_);
    sha256_com.UpdateBN(b_);
    blind_a_b_ = RandomBytes(32);
    std::string c2 = sha256_com.Commit(blind_a_b_);

    Q_prime_ = Q_ * a_ + curv->g * b_;

    v_message1.c1_ = c1;
    v_message1.c2_ = c2;

    return true;
}

bool PDLVerifier::Step2(const PDLPMessage1 &p_message1, PDLVMessage2 &v_message2){
    commit_Q_hat_ = p_message1.commit_Q_hat_;
    v_message2.a_ = a_;
    v_message2.b_ = b_;
    v_message2.blind_a_b_ = blind_a_b_;
    return true;
}

bool PDLVerifier::Accept(const PDLPMessage2 &p_message2) const {
    bool accepted = true;
    HashCommit256 sha256_com;
    sha256_com.UpdateCurvePoint(p_message2.Q_hat_);
    accepted = sha256_com.OpenAndVerify(p_message2.blind_Q_hat_, commit_Q_hat_);
    if (!accepted) return false;

    accepted = Q_prime_ == p_message2.Q_hat_;
    if (!accepted) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(Q_.GetCurveType());
    const safeheron::bignum::BN q = curv->n;
    const safeheron::bignum::BN l = q / 3;

    const safeheron::bignum::BN c_minus_l = pail_pub_.HomomorphicAddPlain(c_, pail_pub_.n() - l);

    safeheron::zkp::pail::PailEncRangeStatement_V3 statement(c_minus_l, pail_pub_, l);
    safeheron::zkp::pail::PailEncRangeProof_V3 pail_enc_rang_proof =  p_message2.pail_enc_rang_proof_;
    if (!salt_.empty()) pail_enc_rang_proof.SetSalt(salt_);

    accepted = pail_enc_rang_proof.Verify(statement);
    return accepted;
}


}
}
}