#ifndef SAFEHERON_CRYPTO_AUTH_ENC_H
#define SAFEHERON_CRYPTO_AUTH_ENC_H

#include "crypto-bn/bn.h"
#include "crypto-curve/curve_point.h"


namespace safeheron {
namespace ecies {

class AuthEnc{
private:
    safeheron::curve::CurveType curve_type_;
public:
    AuthEnc(){ curve_type_ = safeheron::curve::CurveType::P256; }
    void set_curve_type(safeheron::curve::CurveType curve_type);
    bool Encrypt(const safeheron::bignum::BN &local_priv, const safeheron::curve::CurvePoint &remote_pub, const std::string &in_plain, std::string &out_cypher);
    bool Encrypt(const safeheron::bignum::BN &local_priv, const safeheron::curve::CurvePoint &remote_pub, const unsigned char *in_plain, size_t in_plain_len, unsigned char **out_cypher, size_t *out_cypher_len);
    bool Decrypt(const safeheron::bignum::BN &local_priv, const safeheron::curve::CurvePoint &remote_pub, const std::string &in_cypher, std::string &out_plain);
    bool Decrypt(const safeheron::bignum::BN &local_priv, const safeheron::curve::CurvePoint &remote_pub, const unsigned char *in_cypher, size_t in_cypher_len, unsigned char **out_plain, size_t *out_plain_len);
};

}
}


#endif //SAFEHERON_CRYPTO_AUTH_ENC_H
