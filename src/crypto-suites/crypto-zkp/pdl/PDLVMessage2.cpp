#include "pdl_message.h"

#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-encode/base64.h"

using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron {
namespace zkp {
namespace pdl {

bool PDLVMessage2::ToProtoObject(safeheron::proto::PDLVMessage2 &v_message2) const {
    std::string str;
    a_.ToHexStr(str);
    v_message2.set_a(str);
    b_.ToHexStr(str);
    v_message2.set_b(str);
    v_message2.set_blind_a_b(safeheron::encode::hex::EncodeToHex(blind_a_b_));

    return true;
}

bool PDLVMessage2::FromProtoObject(const safeheron::proto::PDLVMessage2 &v_message2) {
    a_ = safeheron::bignum::BN::FromHexStr(v_message2.a());
    b_ = safeheron::bignum::BN::FromHexStr(v_message2.b());
    blind_a_b_ = safeheron::encode::hex::DecodeFromHex(v_message2.blind_a_b());
    return true;
}

typedef PDLVMessage2 TheClass;
typedef safeheron::proto::PDLVMessage2 ProtoObject;

bool TheClass::ToBase64(std::string &b64) const {
    bool ok = true;
    b64.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    std::string proto_bin = proto_object.SerializeAsString();
    b64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const std::string &b64) {
    bool ok = true;

    std::string data = safeheron::encode::base64::DecodeFromBase64(b64);

    ProtoObject proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool TheClass::ToJsonString(std::string &json_str) const {
    bool ok = true;
    json_str.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool TheClass::FromJsonString(const std::string &json_str) {
    ProtoObject proto_object;
    JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}