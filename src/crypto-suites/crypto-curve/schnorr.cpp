#include "crypto-suites/exception/safeheron_exceptions.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-hash/sha256.h"
#include "crypto-suites/crypto-hash/hash_bip340.h"
#include "crypto-suites/crypto-curve/schnorr.h"
#include "crypto-suites/crypto-encode/hex.h"

using safeheron::exception::LocatedException;
using safeheron::hash::CSHA256;
using safeheron::hash::CTaggedSHA256;
using safeheron::hash::CHashBIP340Nonce;
using safeheron::hash::CHashBIP340Aux;
using safeheron::hash::CHashBIP340Challenge;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;

namespace safeheron{
namespace curve {
namespace schnorr {

bool has_even_y(const safeheron::curve::CurvePoint &point){
    return !point.IsInfinity() && point.y().IsEven();
}

void bip340_get_deterministic_nonce(const char secret[32],
                             const char * p_P, size_t P_len,
                             const char * p_aux_rand, size_t aux_rand_len,
                             const char * p_msg, size_t msg_len,
                             uint8_t nonce[32]){
    //    Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(aux_rand).
    uint8_t t[32] = {0};
    CHashBIP340Aux hash_bip340_aux;
    hash_bip340_aux.Write(reinterpret_cast<const uint8_t *>(p_aux_rand), aux_rand_len);
    hash_bip340_aux.Finalize(t);
    for(int i = 0; i < 32; ++i){
        t[i] = secret[i] ^ t[i];
    }

    //    Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].
    CHashBIP340Nonce hash_bip340_nonce;
    hash_bip340_nonce.Write(reinterpret_cast<const uint8_t *>(t), sizeof t);
    hash_bip340_nonce.Write(reinterpret_cast<const uint8_t *>(p_P), P_len);
    hash_bip340_nonce.Write(reinterpret_cast<const uint8_t *>(p_msg), msg_len);
    hash_bip340_nonce.Finalize(nonce);

}

bool schnorr_bip340_verify(const CurveType c_type, const CurvePoint &pub,
                  const uint8_t *sig, const uint8_t *msg, size_t msg_len){
    if( c_type != CurveType::SECP256K1 ){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, " c_type != CurveType::ED25519 ");
    }

    const safeheron::curve::Curve * curv = GetCurveParam(c_type);

    //  Let P = lift_x(int(pk)); fail if that fails.
    CurvePoint P = pub;
    if( P.IsInfinity() ) return false;
    if(!has_even_y(P)) P = P.Neg();

    //  Let r = int(sig[0:32]); fail if r ≥ p.
    const BN r = BN::FromBytesBE(sig, 32);
    if( r >= curv->p ) return false;

    //  Let s = int(sig[32:64]); fail if s ≥ n.
    const BN s = BN::FromBytesBE(sig + 32, 32);
    if( s >= curv->n ) return false;

    //  Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
    uint8_t t_hash[32];
    std::string P_bytes;
    P.x().ToBytes32BE(P_bytes);
    CHashBIP340Challenge hash_bip340_challenge;
    hash_bip340_challenge.Write(reinterpret_cast<const uint8_t *>(sig), 32);
    hash_bip340_challenge.Write(reinterpret_cast<const uint8_t *>(P_bytes.c_str()), 32);
    hash_bip340_challenge.Write(msg, msg_len);
    hash_bip340_challenge.Finalize(t_hash);
    BN e = safeheron::bignum::BN::FromBytesBE(t_hash, sizeof t_hash);
    e = e % curv->n;

    //  Let R = s⋅G - e⋅P.
    CurvePoint R = curv->g * s - P * e;

    //  Fail if is_infinite(R).
    if( R.IsInfinity() ) return false;

    //  Fail if not has_even_y(R).
    if( !has_even_y(R) ) return false;

    //  Fail if x(R) ≠ r.
    if(R.x() != r) return false;

    //  Return success iff no failure occurred before reaching this point.
    return true;
}

std::string schnorr_bip340_sign(const CurveType c_type,
                 const safeheron::bignum::BN &priv,
                 const uint8_t *msg, size_t msg_len,
                 const std::string &aux){
    if( c_type != CurveType::SECP256K1){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "c_type != CurveType::SECP256K1");
    }
    const safeheron::curve::Curve * curv = GetCurveParam(c_type);

    //    Let d' = int(sk)
    const BN &d_prime = priv;

    //    Fail if d' = 0 or d' ≥ n
    if( d_prime == 0 || d_prime >= curv->n ){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "d_prime == 0 || d_prime >= curv->n");
    }

    //    Let P = d'⋅G
    const CurvePoint P = curv->g * d_prime;
    if(P.IsInfinity()){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "P.IsInfinity()");
    }
    std::string P_bytes;
    P.x().ToBytes32BE(P_bytes);

    //    Let d = d' if has_even_y(P), otherwise let d = n - d' .
    BN d = d_prime;
    if( !has_even_y(P) ) d = curv->n - d_prime;

    //    Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)[11].
    //    Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].
    uint8_t rand[32] = {0};
    uint8_t d_bytes[32] = {0};
    d.ToBytes32BE(d_bytes, sizeof d_bytes);
    bip340_get_deterministic_nonce(reinterpret_cast<const char *>(d_bytes),
                            P_bytes.c_str(), P_bytes.length(),
                            aux.c_str(), aux.length(),
                            reinterpret_cast<const char *>(msg), msg_len,
                            rand);

    //    Let k' = int(rand) mod n[13].
    //    Fail if k' = 0.
    safeheron::bignum::BN k_prime = BN::FromBytesBE(rand, sizeof rand);
    k_prime = k_prime % curv->n;

    //    Let R = k'⋅G.
    safeheron::curve::CurvePoint R = curv->g * k_prime;
    std::string R_bytes;
    R.x().ToBytes32BE(R_bytes);

    //    Let k = k' if has_even_y(R), otherwise let k = n - k' .
    BN k = k_prime;
    if( !has_even_y(R) ) k = curv->n - k_prime;

    //    Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
    uint8_t t_hash[32];
    // BIP340
    CHashBIP340Challenge hash_bip340_challenge;
    hash_bip340_challenge.Write(reinterpret_cast<const uint8_t *>(R_bytes.c_str()), R_bytes.length());
    hash_bip340_challenge.Write(reinterpret_cast<const uint8_t *>(P_bytes.c_str()), P_bytes.length());
    hash_bip340_challenge.Write(msg, msg_len);
    hash_bip340_challenge.Finalize(t_hash);
    BN e = safeheron::bignum::BN::FromBytesBE(t_hash, sizeof t_hash);
    e = e % curv->n;

    //    Let sig = bytes(R) || bytes((k + ed) mod n).
    BN s = (k + e * d) % curv->n;
    uint8_t sig[64] = {0};
    R.x().ToBytes32BE(sig, 32);
    s.ToBytes32BE(sig + 32, 32);

    //    If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
    //    Return the signature sig.
    if(!Verify(c_type, P, sig, msg, msg_len, safeheron::curve::schnorr::SchnorrPattern::BIP340)){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "!Verify(c_type, P, sig, msg.c_str(), msg.length(), tag)");
    }

    std::string ret(reinterpret_cast<const char *>(sig), sizeof sig);
    return ret;
}

bool schnorr_legacy_verify(const CurveType c_type, const CurvePoint &pub,
                  const uint8_t *sig, const uint8_t *msg, size_t msg_len){
    if( c_type != CurveType::SECP256K1 ){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, " c_type != CurveType::SECP256K1 ");
    }

    const safeheron::curve::Curve * curv = GetCurveParam(c_type);

    //  Let P = lift_x(int(pk)); fail if that fails.
    CurvePoint P = pub;
    if( P.IsInfinity() ) return false;

    //  Let r = int(sig[0:32]); fail if r ≥ p.
    const BN r = BN::FromBytesBE(sig, 32);
    if( r >= curv->p ) return false;

    //  Let s = int(sig[32:64]); fail if s ≥ n.
    const BN s = BN::FromBytesBE(sig + 32, 32);
    if( s >= curv->n ) return false;

    //  Let e = int(hash(bytes(r) || bytes(P) || m)) mod n.
    uint8_t t_hash[32];
    std::string P_compressed_bytes;
    P.EncodeCompressed(P_compressed_bytes);
    CSHA256 sha256;
    sha256.Write(reinterpret_cast<const uint8_t *>(sig), 32);
    sha256.Write(reinterpret_cast<const uint8_t *>(P_compressed_bytes.c_str()), P_compressed_bytes.length());
    sha256.Write(msg, msg_len);
    sha256.Finalize(t_hash);
    BN e = safeheron::bignum::BN::FromBytesBE(t_hash, sizeof t_hash);
    e = e % curv->n;

    //  Let R = s⋅G - e⋅P.
    CurvePoint R = curv->g * s - P * e;

    //  Fail if is_infinite(R).
    if( R.IsInfinity() ) return false;

    //  Fail if R's y coordinate is not a quadratic residue.
    if( !R.y().ExistSqrtM(curv->p) ) return false;

    //  Fail if x(R) ≠ r.
    if(R.x() != r) return false;

    //  Return success iff no failure occurred before reaching this point.
    return true;
}

std::string schnorr_legacy_sign(const CurveType c_type,
                 const safeheron::bignum::BN &priv,
                 const uint8_t *msg, size_t msg_len){
    if( c_type != CurveType::SECP256K1){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "c_type != CurveType::SECP256K1");
    }
    const safeheron::curve::Curve * curv = GetCurveParam(c_type);

    const BN& d = priv;

    // Fail if d = 0
    if( d == 0 || d >= curv->n ){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "d == 0 || d >= curv->n");
    }

    //  Let P = G^d
    const CurvePoint P = curv->g * d;
    if(P.IsInfinity()){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "P.IsInfinity()");
    }
    std::string P_compressed_bytes;
    P.EncodeCompressed(P_compressed_bytes);

    // Generate Random k and R = g^k
    BN k(0);
    do{
        k = safeheron::rand::RandomBNLt(curv->n);
    } while (k == 0);
    CurvePoint R = curv->g * k;

    /**
     * If R's y coordinate is not a quadratic residue, which is not allowed.
     * Negate the nonce to ensure it is.
     */
    if(!R.y().ExistSqrtM(curv->p)){
        k = curv->n - k;
        R = R.Neg();
    }
    std::string R_bytes;
    R.x().ToBytes32BE(R_bytes);

    //  Let e = int(hash(bytes(R) || bytes(P) || m)) mod n.
    uint8_t t_hash[32];
    CSHA256 sha256;
    sha256.Write(reinterpret_cast<const uint8_t *>(R_bytes.c_str()), R_bytes.length());
    sha256.Write(reinterpret_cast<const uint8_t *>(P_compressed_bytes.c_str()), P_compressed_bytes.length());
    sha256.Write(msg, msg_len);
    sha256.Finalize(t_hash);
    BN e = safeheron::bignum::BN::FromBytesBE(t_hash, sizeof t_hash);
    e = e % curv->n;

    //  Let sig = bytes(R) || bytes((k + ed) mod n).
    BN s = (k + e * d) % curv->n;
    uint8_t sig[64] = {0};
    R.x().ToBytes32BE(sig, 32);
    s.ToBytes32BE(sig + 32, 32);

    //  If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
    //  Return the signature sig.
    if(!schnorr_legacy_verify(c_type, P, sig, msg, msg_len)){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "!Verify(c_type, P, sig, msg.c_str(), msg.length(), tag)");
    }

    std::string ret(reinterpret_cast<const char *>(sig), sizeof sig);
    return ret;
}

std::string Sign(const CurveType c_type,
                 const safeheron::bignum::BN &priv,
                 const uint8_t *msg, size_t msg_len,
                 const std::string &aux,
                 SchnorrPattern pattern){
    if( c_type != CurveType::SECP256K1){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "c_type != CurveType::SECP256K1");
    }
    const safeheron::curve::Curve * curv = GetCurveParam(c_type);

    if(pattern == SchnorrPattern::Legacy){
        return schnorr_legacy_sign(c_type, priv, msg, msg_len);
    } else{
        return schnorr_bip340_sign(c_type, priv, msg, msg_len,aux);
    }
}

bool Verify(const CurveType c_type, const CurvePoint &pub,
            const uint8_t *sig, const uint8_t *msg, size_t msg_len,
            SchnorrPattern pattern){
    if( c_type != CurveType::SECP256K1 ){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, " c_type != CurveType::SECP256K1 ");
    }
    if(pattern == SchnorrPattern::Legacy){
        return schnorr_legacy_verify(c_type, pub, sig, msg, msg_len);
    } else{
        return schnorr_bip340_verify(c_type, pub, sig, msg, msg_len);
    }
}

}
}
}
