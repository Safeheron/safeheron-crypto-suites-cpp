#ifndef SAFEHERON_CRYPTO_ZKP_PDL_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PDL_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"
#include "crypto-paillier/pail.h"

namespace safeheron{
namespace zkp {
namespace pdl {

/**
 * @brief This protocol is a zero knowledge proof on Paillier Encryption of the discrete of Q.
 *
 * Statement: δ = (c, pail_pub, Q), where:
 * Witness:   ω = (x, r) where x in (0, q), r in ZN*
 * Prove relation: c = Enc(pail_pub, x, r) and Q = xG
 *
 * Process:
 * V: message1(c1, c2) => P
 * P: message2(commit(Q)) => V
 * V: message3(a, b) => P
 * P: message4( decommit(Q) ) => V
 * V: Accept
 *
 * Reference
 * - Section 6 in [Lindell'17](https://eprint.iacr.org/2017/552)
 */

class PDLVerifier {
public:
    PDLVerifier(const safeheron::bignum::BN &c, const safeheron::curve::CurvePoint &Q, const safeheron::pail::PailPubKey &pail_pub) {
        c_ = c;
        Q_ = Q;
        pail_pub_ = pail_pub;
    }

    bool Step1(safeheron::bignum::BN &c1, safeheron::bignum::BN &c2);
    bool Step2(const safeheron::bignum::BN &commit_Q, safeheron::bignum::BN &a, safeheron::bignum::BN &b, safeheron::bignum::BN &blind_a_b);
    bool Accept(const safeheron::curve::CurvePoint &Q_hat, const safeheron::bignum::BN &blind_Q_hat) const;

private:
    safeheron::bignum::BN c_;
    safeheron::curve::CurvePoint Q_;
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::curve::CurvePoint expected_Q_hat_;
    safeheron::bignum::BN commit_Q_hat_;
    safeheron::bignum::BN a_;
    safeheron::bignum::BN b_;
    safeheron::bignum::BN blind_a_b_;
    safeheron::bignum::BN c1_; // c'
    safeheron::bignum::BN c2_; // c'' = commitment(a, b)
};

class PDLProver {
public:
    PDLProver(const safeheron::bignum::BN &c, const safeheron::curve::CurvePoint &Q, const safeheron::pail::PailPubKey &pail_pub,
              const safeheron::pail::PailPrivKey &pail_priv, const safeheron::bignum::BN &x){
        x_ = x;
        pail_priv_ = pail_priv;
        c_ = c;
        Q_ = Q;
        pail_pub_ = pail_pub;
    }

    bool Step1(const safeheron::bignum::BN &c1, const safeheron::bignum::BN &c2, safeheron::bignum::BN &commit_Q);
    bool Step2(const safeheron::bignum::BN &a, const safeheron::bignum::BN &b, const safeheron::bignum::BN &blind_a_b,
               safeheron::curve::CurvePoint &Q_hat, safeheron::bignum::BN &blind_Q_hat);

private:
    safeheron::bignum::BN x_;
    safeheron::bignum::BN r_;
    safeheron::pail::PailPrivKey pail_priv_;
    safeheron::bignum::BN c_;
    safeheron::curve::CurvePoint Q_;
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::curve::CurvePoint Q_Prime_;
    safeheron::curve::CurvePoint Q_hat_;
    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN c2_; // c''
    safeheron::bignum::BN blind_Q_hat_;

};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PDL_PROOF_H
