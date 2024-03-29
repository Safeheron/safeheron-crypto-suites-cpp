#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/commitment.h"

using safeheron::bignum::BN;
using safeheron::hash::CSafeHash256;
using safeheron::curve::CurvePoint;

namespace safeheron{
namespace commitment {

BN CreateComWithBlind(const BN &num, const BN &blind_factor) {
    uint8_t digest[CSafeHash256::OUTPUT_SIZE];
    CSafeHash256 sha256;
    std::string buf;
    num.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());
    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());
    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSafeHash256::OUTPUT_SIZE);
}

BN CreateComWithBlind(const std::vector<BN> &num_arr, const BN &blind_factor) {
    uint8_t digest[CSafeHash256::OUTPUT_SIZE];
    CSafeHash256 sha256;
    std::string buf;
    for(size_t i = 0; i < num_arr.size(); ++i) {
        num_arr[i].ToBytesBE(buf);
        sha256.Write((const uint8_t *) buf.c_str(), buf.length());
    }
    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());
    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSafeHash256::OUTPUT_SIZE);
}

BN CreateComWithBlind(const CurvePoint &point, const BN &blind_factor) {
    uint8_t digest[CSafeHash256::OUTPUT_SIZE];
    CSafeHash256 sha256;
    std::string buf;
    point.EncodeFull(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());

    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());

    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSafeHash256::OUTPUT_SIZE);
}

BN CreateComWithBlind(const std::vector<CurvePoint> &points, const BN &blind_factor) {
    uint8_t digest[CSafeHash256::OUTPUT_SIZE];
    CSafeHash256 sha256;
    std::string buf;
    for(size_t i = 0; i < points.size(); ++i) {
        points[i].EncodeFull(buf);
        sha256.Write((const uint8_t *) buf.c_str(), buf.length());
    }

    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());

    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSafeHash256::OUTPUT_SIZE);
}

}
}