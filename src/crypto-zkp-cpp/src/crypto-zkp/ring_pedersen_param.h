#ifndef SAFEHERON_CRYPTO_ZKP_DLN_RING_PEDERSEN_PARAM_PUB_H
#define SAFEHERON_CRYPTO_ZKP_DLN_RING_PEDERSEN_PARAM_PUB_H
#include "crypto-bn/bn.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace dln_proof{

class RingPedersenParamPub {
public:
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN h1_;
    safeheron::bignum::BN h2_;

public:
    bool ToProtoObject(safeheron::proto::RingPedersenParamPub &param) const;

    bool FromProtoObject(const safeheron::proto::RingPedersenParamPub &param);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);

};

class RingPedersenParamPriv {
public:
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;
    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN beta_;

public:
    bool ToProtoObject(safeheron::proto::RingPedersenParamPriv &param) const;

    bool FromProtoObject(const safeheron::proto::RingPedersenParamPriv &param);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);

};

}
}
}

#endif //SAFEHERON_CRYPTO_ZKP_DLN_RING_PEDERSEN_PARAM_PUB_H
