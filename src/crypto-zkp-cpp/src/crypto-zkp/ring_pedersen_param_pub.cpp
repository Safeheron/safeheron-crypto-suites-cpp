#include "ring_pedersen_param.h"
#include "crypto-encode/base64.h"
#include <google/protobuf/util/json_util.h>

using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron{
namespace zkp {
namespace dln_proof{

bool RingPedersenParamPub::ToProtoObject(safeheron::proto::RingPedersenParamPub &param) const {
    string str;

    N_tilde_.ToHexStr(str);
    param.set_n_tilde(str);

    h1_.ToHexStr(str);
    param.set_h1(str);

    h2_.ToHexStr(str);
    param.set_h2(str);

    return true;
}

bool RingPedersenParamPub::FromProtoObject(const safeheron::proto::RingPedersenParamPub &param) {
    N_tilde_ = BN::FromHexStr(param.n_tilde());
    h1_ = BN::FromHexStr(param.h1());
    h2_ = BN::FromHexStr(param.h2());
    return true;
}

typedef RingPedersenParamPub TheClass;
typedef safeheron::proto::RingPedersenParamPub ProtoObject;
bool TheClass::ToBase64(std::string &base64) const {
    base64.clear();
    ProtoObject proto_object;
    bool ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    base64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const std::string &base64) {
    string data = safeheron::encode::base64::DecodeFromBase64(base64);

    ProtoObject proto_object;
    bool ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool TheClass::ToJsonString(std::string &json_str) const {
    json_str.clear();
    ProtoObject proto_object;
    bool ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool TheClass::FromJsonString(const std::string &json_str) {
    ProtoObject proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}


}
}
}