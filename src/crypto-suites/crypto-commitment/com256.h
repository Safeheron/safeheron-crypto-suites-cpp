#ifndef SAFEHERONCRYPTOSUITES_COMMITMENT_COM256_H
#define SAFEHERONCRYPTOSUITES_COMMITMENT_COM256_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"

namespace safeheron {
namespace commitment {

class Com256 {
private:
    safeheron::hash::CSafeHash256 sha;
public:
    static const size_t OUTPUT_SIZE = safeheron::hash::CSafeHash256::OUTPUT_SIZE;

    Com256& CommitBN(const safeheron::bignum::BN &num);
    Com256& CommitCurvePoint(const safeheron::curve::CurvePoint &point);
    Com256& CommitString(const std::string &str);
    Com256& CommitBytes(const unsigned char *data, size_t len);

    void Finalize(const std::string &blind_factor, unsigned char com[OUTPUT_SIZE]);
    void Finalize(const std::string &blind_factor, std::string &com);

    Com256& Reset();
};


} // safeheron
} // commitment

#endif //SAFEHERONCRYPTOSUITES_COMMITMENT_COM256_H
