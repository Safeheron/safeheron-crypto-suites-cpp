#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/kgd_number.h"

using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;

namespace safeheron{
namespace commitment{

bool KgdNumber::ToProtoObject(safeheron::proto::KGD_Num &kgd_num) const {
    string str;
    num_.ToHexStr(str);
    kgd_num.set_num(str);

    blind_factor_.ToHexStr(str);
    kgd_num.set_blindfactor(str);

    return true;
}

bool KgdNumber::FromProtoObject(const safeheron::proto::KGD_Num &kgd_num) {
    bool ok = true;
    num_ = BN::FromHexStr(kgd_num.num());
    ok = (num_ != 0);
    if (!ok) return false;

    blind_factor_ = BN::FromHexStr(kgd_num.blindfactor());
    ok = (blind_factor_ != 0);
    if (!ok) return false;

    return true;
}

bool KgdNumber::ToBase64(string &b64) const {
    b64.clear();
    safeheron::proto::KGD_Num proto_object;
    ToProtoObject(proto_object);
    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool KgdNumber::FromBase64(const string &base64) {
    bool ret = true;

    string data = base64::DecodeFromBase64(base64);
    if (!ret) return false;

    safeheron::proto::KGD_Num proto_object;
    ret = proto_object.ParseFromString(data);
    if (!ret) return false;

    return FromProtoObject(proto_object);
}

bool KgdNumber::ToJsonString(string &json_str) const {
    bool ret = true;
    json_str.clear();
    safeheron::proto::KGD_Num proto_object;
    ret = ToProtoObject(proto_object);
    if (!ret) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool KgdNumber::FromJsonString(const string &json_str) {
    safeheron::proto::KGD_Num proto_object;
    JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    return FromProtoObject(proto_object);
}

}
}
