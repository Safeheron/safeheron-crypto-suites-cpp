#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/kgd_curve_point.h"

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

bool KgdCurvePoint::ToProtoObject(safeheron::proto::KGD &kgd_num) const {
    bool ok = true;
    safeheron::proto::CurvePoint point;
    ok = point_.ToProtoObject(point);
    kgd_num.mutable_y()->CopyFrom(point);
    if (!ok) return false;

    string str;
    blind_factor_.ToHexStr(str);
    kgd_num.set_blindfactor(str);

    return true;
}

bool KgdCurvePoint::FromProtoObject(const safeheron::proto::KGD &kgd_num) {
    bool ok = true;
    ok = point_.FromProtoObject(kgd_num.y());
    ok = ok && !point_.IsInfinity();
    if (!ok) return false;

    blind_factor_ = BN::FromHexStr(kgd_num.blindfactor());
    ok = (blind_factor_ != 0);
    if (!ok) return false;

    return true;
}

bool KgdCurvePoint::ToBase64(string &b64) const {
    b64.clear();
    safeheron::proto::KGD proto_object;
    ToProtoObject(proto_object);
    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool KgdCurvePoint::FromBase64(const string &base64) {
    bool ret = true;

    string data = base64::DecodeFromBase64(base64);
    if (!ret) return false;

    safeheron::proto::KGD proto_object;
    ret = proto_object.ParseFromString(data);
    if (!ret) return false;

    return FromProtoObject(proto_object);
}

bool KgdCurvePoint::ToJsonString(string &json_str) const {
    bool ret = true;
    json_str.clear();
    safeheron::proto::KGD proto_object;
    ret = ToProtoObject(proto_object);
    if (!ret) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool KgdCurvePoint::FromJsonString(const string &json_str) {
    safeheron::proto::KGD proto_object;
    JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    return FromProtoObject(proto_object);
}

}
}
