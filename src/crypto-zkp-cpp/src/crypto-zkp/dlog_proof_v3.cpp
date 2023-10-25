#include "dlog_proof_v3.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::hash::CSHA256;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;
using namespace safeheron::rand;

namespace safeheron{
namespace zkp {
namespace dlog {

void DLogProof_V3::Prove(const BN &x, const CurvePoint &G, const BN &order) {
    BN alpha = RandomBNLt(order);
    ProveWithR(x, G, order, alpha);
}

void DLogProof_V3::ProveWithR(const BN &x, const CurvePoint &G, const BN &order, const BN &alpha) {
    A_ = G * alpha;
    CurvePoint X = G * x;

    // c = H(G || g^alpha || g^x || UserID || OtherInfo)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    G.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    G.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, 32);
    e = e % order;

    // z = alpha + e * x mod q
    z_ = (alpha + e * x) % order;
}

bool DLogProof_V3::Verify(const curve::CurvePoint &X, const curve::CurvePoint &G, const BN &order) const {
    // e = H(G || g^alpha || g^x || UserID || OtherInfo)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    G.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    G.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, 32);
    e = e % order;

    // Verify: g^z === A * X^e
    CurvePoint left_point = G * z_;
    CurvePoint right_point = A_ + X * e;
    return left_point == right_point;
}

bool DLogProof_V3::ToProtoObject(safeheron::proto::DLogProof_V2 &dlog_proof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;

    // A = g^r
    ok = A_.ToProtoObject(tmp);
    if (!ok) return false;
    dlog_proof.mutable_a()->CopyFrom(tmp);

    // z
    std::string str;
    z_.ToHexStr(str);
    dlog_proof.set_z(str);

    return true;
}

bool DLogProof_V3::FromProtoObject(const safeheron::proto::DLogProof_V2 &dlog_proof) {
    bool ok = true;
    safeheron::proto::CurvePoint point;
    // A = g^r
    point = dlog_proof.a();
    ok = A_.FromProtoObject(point);
    if (!ok) return false;

    // z
    z_ = BN::FromHexStr(dlog_proof.z());

    return true;
}

bool DLogProof_V3::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::DLogProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool DLogProof_V3::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::DLogProof_V2 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool DLogProof_V3::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::DLogProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool DLogProof_V3::FromJsonString(const string &json_str) {
    safeheron::proto::DLogProof_V2 proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
