#include "auth_enc.h"
#include "ecies.h"
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "exception/safeheron_exceptions.h"
#include "crypto-hash/sha256.h"
#include "crypto-encode/hex.h"

using namespace safeheron::bignum;
using namespace safeheron::curve;
using namespace safeheron::hash;

namespace safeheron {
namespace ecies {

void AuthEnc::set_curve_type(CurveType curve_type) {
    curve_type_ = curve_type;
}

bool AuthEnc::Encrypt(const BN &local_priv, const CurvePoint &remote_pub, 
                      const unsigned char *in_plain, size_t in_plain_len,
                      unsigned char **out_cypher, size_t *out_cypher_len) {
    bool ok = true;
    uint8_t digest[32] = {0};
    unsigned char sig[64] = {0};
    std::string data_for_encrypt;
    std::string raw_cypher;
    CurveType c_type = remote_pub.GetCurveType();
    const Curve * curv = GetCurveParam(c_type);
    if(curv == nullptr) return false;

    if (!in_plain || in_plain_len <= 0) {
        return false;
    }

    // Get digest of olain data
    CSHA256 sha256;
    sha256.Write(in_plain, in_plain_len);
    sha256.Finalize(digest);

    try {
        // Sign
        safeheron::curve::ecdsa::Sign(c_type, local_priv, digest, sig);
    }
    catch(safeheron::exception::OpensslException e) {
        return false;
    }

    // Encrypt plain||sign
    ECIES ecies;
    ecies.set_curve_type(c_type);
    data_for_encrypt.append((const char*)in_plain, in_plain_len);
    data_for_encrypt.append((const char*)sig, 64);
    ok = ecies.EncryptPack(remote_pub, data_for_encrypt, raw_cypher);
    if (!ok) return false;

    // Construct the output
    *out_cypher_len = raw_cypher.length();
    *out_cypher = (unsigned char *) malloc(*out_cypher_len);
    memcpy(*out_cypher, raw_cypher.c_str(), raw_cypher.length());

    return true;
}

bool AuthEnc::Decrypt(const BN &local_priv, const CurvePoint &remote_pub, 
                      const unsigned char *in_cypher, size_t in_cypher_len,
                      unsigned char **out_plain, size_t *out_plain_len) {
    bool ok = true;
    std::string decrypted;
    std::string t_plain;
    unsigned char sig[64] = {0};
    CurveType c_type = remote_pub.GetCurveType();
    if(c_type == CurveType::INVALID_CURVE) return false;

    if (!in_cypher || in_cypher_len <= 0) {
        return false;
    }

    // Decrypt
    ECIES ecies;
    ecies.set_curve_type(c_type);
    ok = ecies.DecryptPack(local_priv, in_cypher, in_cypher_len, decrypted);
    if (!ok) return false;

    // Get plain and sign from decrypted result
    t_plain.assign((const char*)decrypted.c_str(), decrypted.length() - 64);
    memcpy(sig, (const char*)(decrypted.c_str() + decrypted.length() - 64), 64);

    // Get digest of plain data
    uint8_t digest[32];
    CSHA256 sha256;
    sha256.Write((const unsigned char*)t_plain.c_str(), t_plain.length());
    sha256.Finalize(digest);

    // Verify signature
    try {
        ok = safeheron::curve::ecdsa::Verify(c_type, remote_pub, digest, sig);
        if (!ok) return false;
    }
    catch (safeheron::exception::LocatedException e) {
        return false;
    }

    *out_plain_len = t_plain.length();
    *out_plain = (unsigned char *) malloc(*out_plain_len);
    memcpy(*out_plain, t_plain.c_str(), t_plain.length());

    return true;
}

bool AuthEnc::Encrypt(const BN &local_priv, const CurvePoint &remote_pub, 
                      const std::string &in_plain, std::string &out_cypher) {
    uint8_t * t_cypher = nullptr;
    size_t t_cypher_len = 0;
    bool ok = Encrypt(local_priv, remote_pub, (unsigned char *)in_plain.c_str(), in_plain.length(), &t_cypher, &t_cypher_len);
    if(!ok) return false;
    out_cypher.assign((const char*)t_cypher, t_cypher_len);
    free(t_cypher);
    return true;
}

bool AuthEnc::Decrypt(const BN &local_priv, const CurvePoint &remote_pub, 
                      const std::string &in_cypher, std::string &out_plain) {
    unsigned char *t_plain = nullptr;
    size_t t_plain_len = 0;
    bool ok = Decrypt(local_priv, remote_pub, (const unsigned char *)in_cypher.c_str(), in_cypher.length(), &t_plain, &t_plain_len);
    if(!ok) return false;
    out_plain.assign((char *)t_plain, t_plain_len);
    free(t_plain);
    return true;
}

}
}
