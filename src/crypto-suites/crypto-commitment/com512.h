#ifndef SAFEHERONCRYPTOSUITES_COMMITMENT_COM512_H
#define SAFEHERONCRYPTOSUITES_COMMITMENT_COM512_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-hash/safe_hash512.h"

namespace safeheron {
namespace commitment {

class Com512 {
private:
    safeheron::hash::CSafeHash512 sha;
public:
    static const size_t OUTPUT_SIZE = safeheron::hash::CSafeHash512::OUTPUT_SIZE;

    Com512& CommitBN(const safeheron::bignum::BN &num);
    Com512& CommitCurvePoint(const safeheron::curve::CurvePoint &point);
    Com512& CommitString(const std::string &str);
    Com512& CommitBytes(const unsigned char *data, size_t len);

    void Finalize(const std::string &blind_factor, unsigned char com[OUTPUT_SIZE]);
    void Finalize(const std::string &blind_factor, std::string &com);

    Com512& Reset();
};


} // safeheron
} // commitment

#endif //SAFEHERONCRYPTOSUITES_COMMITMENT_COM512_H
