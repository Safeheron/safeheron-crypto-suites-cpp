#include "commitment.h"
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"

using safeheron::bignum::BN;
using safeheron::hash::CSHA256;
using safeheron::curve::CurvePoint;

namespace safeheron{
namespace commitment {

BN CreateComWithBlind(const BN &num, const BN &blind_factor) {
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    num.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());
    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());
    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);
}

BN CreateComWithBlind(const std::vector<BN> &num_arr, const BN &blind_factor) {
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    for(size_t i = 0; i < num_arr.size(); ++i) {
        num_arr[i].ToBytesBE(buf);
        sha256.Write((const uint8_t *) buf.c_str(), buf.length());
    }
    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());
    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);
}

BN CreateComWithBlind(const CurvePoint &point, const BN &blind_factor) {
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    point.x().ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());
    point.y().ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());

    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());

    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);
}

BN CreateComWithBlind(const std::vector<CurvePoint> &points, const BN &blind_factor) {
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    for(size_t i = 0; i < points.size(); ++i) {
        points[i].x().ToBytesBE(buf);
        sha256.Write((const uint8_t *) buf.c_str(), buf.length());
        points[i].y().ToBytesBE(buf);
        sha256.Write((const uint8_t *) buf.c_str(), buf.length());
    }

    blind_factor.ToBytesBE(buf);
    sha256.Write((const uint8_t*)buf.c_str(), buf.length());

    sha256.Finalize(digest);
    return BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);
}

}
}