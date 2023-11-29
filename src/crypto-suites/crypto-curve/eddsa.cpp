#include "eddsa.h"
#include "../exception/safeheron_exceptions.h"
#include "../crypto-bn/rand.h"
#include "../crypto-hash/sha512.h"
#include "../crypto-encode/hex.h"
#include "ed25519_ex.h"

using safeheron::exception::LocatedException;

namespace safeheron{
namespace curve {
namespace eddsa {

std::string Sign(const CurveType c_type,
                 const safeheron::bignum::BN &secret,
                 const CurvePoint &pub,
                 const uint8_t *msg, size_t len){
    if( c_type != CurveType::ED25519){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "c_type != CurveType::ED25519");
    }

    unsigned char sk[32];
    const curve::Curve *curv = curve::GetCurveParam(c_type);

    secret.ToBytes32LE((uint8_t *)sk);
    ed25519_public_key pub32;
    pub.EncodeEdwardsPoint(pub32) ;
    ed25519_signature RS;
    ed25519_sign(msg, len, sk, pub32, RS);

    std::string ret;
    ret.assign(reinterpret_cast<const char *>(RS), sizeof(ed25519_signature));
    memset(RS, 0, sizeof(ed25519_signature));
    return ret;
}

std::string Sign(const CurveType c_type,
                 const safeheron::bignum::BN &priv,
                 const uint8_t *msg, size_t len){
    if( c_type != CurveType::ED25519){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "c_type != CurveType::ED25519");
    }
    const safeheron::bignum::BN N = GetCurveParam(c_type)->n;
    const safeheron::curve::CurvePoint B = GetCurveParam(c_type)->g;

    uint8_t priv_key[32] = { 0 };
    priv.ToBytes32LE(priv_key);

    uint8_t seed[32] = { 0 };
    safeheron::rand::RandomBytes(seed, 32);

    uint8_t hash[64] = { 0 };
    safeheron::hash::CSHA512 sha512;
    sha512.Write(seed, 32);
    sha512.Write(priv_key, 32);
    sha512.Write(msg, len);
    sha512.Finalize(hash);

    std::string str;
    safeheron::bignum::BN nonce;
    nonce = safeheron::bignum::BN::FromBytesLE(hash, 64);
    nonce = nonce % N;

    uint8_t R_buf[32] = { 0 };
    uint8_t A_buf[32] = { 0 };
    safeheron::curve::CurvePoint R = (B * nonce);
    safeheron::curve::CurvePoint A = (B * priv);
    R.EncodeEdwardsPoint(R_buf);
    A.EncodeEdwardsPoint(A_buf);
    sha512.Reset();
    sha512.Write(R_buf, 32);
    sha512.Write(A_buf, 32);
    sha512.Write(msg, len);
    sha512.Finalize(hash);

    safeheron::bignum::BN hram;
    hram = safeheron::bignum::BN::FromBytesLE(hash, 64);
    hram = hram % N;

    uint8_t S_buf[32] = { 0 };
    safeheron::bignum::BN S;
    S = hram * priv;
    S += nonce;
    S = S % N;
    S.ToBytes32LE(S_buf);

    ed25519_signature RS;
    memcpy(RS, R_buf, 32);
    memcpy(RS + 32, S_buf, 32);

    std::string ret;
    ret.assign(reinterpret_cast<const char *>(RS), sizeof(ed25519_signature));
    memset(RS, 0, sizeof(ed25519_signature));
    return ret;
}

bool Verify(const CurveType c_type, const CurvePoint &pub,
            const uint8_t *sig, const uint8_t *msg, size_t len){
    if( c_type != CurveType::ED25519 ){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, " c_type != CurveType::ED25519 ");
    }

    ed25519_public_key pub32;
    pub.EncodeEdwardsPoint(pub32);
    ed25519_signature RS;
    memcpy(RS, sig, sizeof(ed25519_signature));
    return 0 == ed25519_sign_open(msg, len, pub32, RS);
}

}
}
}
