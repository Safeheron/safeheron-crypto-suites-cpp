#ifndef SAFEHERONCRYPTOSUITES_PDL_COMMON_STRUCTURE_H
#define SAFEHERONCRYPTOSUITES_PDL_COMMON_STRUCTURE_H


#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "crypto-suites/crypto-paillier/pail_privkey.h"
#include "crypto-suites/crypto-paillier/pail_pubkey.h"

namespace safeheron{
namespace zkp {
namespace pdl {

struct PDLStatement {
    safeheron::bignum::BN c_;
    safeheron::curve::CurvePoint Q_;
    safeheron::pail::PailPubKey pail_pub_;
    PDLStatement() = default;
    PDLStatement(const safeheron::bignum::BN &c, const safeheron::curve::CurvePoint &Q, const safeheron::pail::PailPubKey &pail_pub): c_(c), Q_(Q), pail_pub_(pail_pub) {}
};

struct PDLWitness {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN r_;
    safeheron::pail::PailPrivKey pail_priv_;
    PDLWitness() = default;
    PDLWitness(const safeheron::bignum::BN &x, const safeheron::bignum::BN &r, const safeheron::pail::PailPrivKey &pail_priv): x_(x), r_(r), pail_priv_(pail_priv) {}
};

}
}
}
#endif //SAFEHERONCRYPTOSUITES_PDL_COMMON_STRUCTURE_H