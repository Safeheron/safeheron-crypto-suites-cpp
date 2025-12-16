#ifndef SAFEHERONCRYPTOSUITES_COMMITMENT_COM256_H
#define SAFEHERONCRYPTOSUITES_COMMITMENT_COM256_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"

namespace safeheron {
namespace commitment {

class HashCommit256 {
private:
    safeheron::hash::CSafeHash256 sha_;
public:
    static const size_t OUTPUT_SIZE = safeheron::hash::CSafeHash256::OUTPUT_SIZE;

    HashCommit256& UpdateBN(const safeheron::bignum::BN &num);
    HashCommit256& UpdateCurvePoint(const safeheron::curve::CurvePoint &point);
    HashCommit256& UpdateString(const std::string &str);
    HashCommit256& UpdateBytes(const unsigned char *data, size_t len);

    std::string Commit(const std::string &blind_factor);
    void Commit(const std::string &blind_factor, unsigned char commitment[OUTPUT_SIZE]);

    bool OpenAndVerify(const std::string &blind_factor, const std::string &commitment);
    bool OpenAndVerify(const std::string &blind_factor, const unsigned char commitment[OUTPUT_SIZE]);

    HashCommit256& Reset();
};


} // safeheron
} // commitment

#endif //SAFEHERONCRYPTOSUITES_COMMITMENT_COM256_H
