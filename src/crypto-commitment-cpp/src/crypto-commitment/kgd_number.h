#ifndef CPP_MPC_KGD_NUMBER_H
#define CPP_MPC_KGD_NUMBER_H

#include "crypto-bn/bn.h"
#include "proto_gen/commitment.pb.switch.h"

namespace safeheron{
namespace commitment {

class KgdNumber {
public:
    safeheron::bignum::BN num_;
    safeheron::bignum::BN blind_factor_;

    KgdNumber() {}

    KgdNumber(safeheron::bignum::BN num, safeheron::bignum::BN blind_factor) {
        num_ = num;
        blind_factor_ = blind_factor;
    }

public:
    bool ToProtoObject(safeheron::proto::KGD_Num &kgdNum) const;
    bool FromProtoObject(const safeheron::proto::KGD_Num &party);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}


#endif //CPP_MPC_KGD_NUMBER_H
