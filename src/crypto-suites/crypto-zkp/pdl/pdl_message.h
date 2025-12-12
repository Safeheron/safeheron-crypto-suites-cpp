#ifndef SAFEHERONCRYPTOSUITES_PDL_MESSAGE_H
#define SAFEHERONCRYPTOSUITES_PDL_MESSAGE_H

#include <string>
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "crypto-suites/crypto-zkp/proto_gen/zkp.pb.switch.h"
#include "crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v3.h"

namespace safeheron {
namespace zkp {
namespace pdl {

class PDLVMessage1 {
public:
    safeheron::bignum::BN c1_;
    std::string c2_;
public:
    bool ToProtoObject(safeheron::proto::PDLVMessage1 &v_message1) const;

    bool FromProtoObject(const safeheron::proto::PDLVMessage1 &v_message1);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class PDLVMessage2 {
public:
    safeheron::bignum::BN a_;
    safeheron::bignum::BN b_;
    std::string blind_a_b_;
public:
    bool ToProtoObject(safeheron::proto::PDLVMessage2 &v_message2) const;

    bool FromProtoObject(const safeheron::proto::PDLVMessage2 &v_message2);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class PDLPMessage1 {
public:
    std::string commit_Q_hat_;
public:
    bool ToProtoObject(safeheron::proto::PDLPMessage1 &p_message1) const;

    bool FromProtoObject(const safeheron::proto::PDLPMessage1 &p_message1);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class PDLPMessage2 {
public:
    safeheron::curve::CurvePoint Q_hat_;
    std::string blind_Q_hat_;

    safeheron::zkp::pail::PailEncRangeProof_V3 pail_enc_rang_proof_;
public:
    bool ToProtoObject(safeheron::proto::PDLPMessage2 &p_message2) const;

    bool FromProtoObject(const safeheron::proto::PDLPMessage2 &p_message2);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

}
}
}

#endif //SAFEHERONCRYPTOSUITES_PDL_MESSAGE_H