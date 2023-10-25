#include "dlog_proof_v2.h"
#include <cassert>
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

DLogProof_V2::DLogProof_V2(curve::CurveType c_type) {
    curv_ = curve::GetCurveParam(c_type);
}

void DLogProof_V2::InternalProve(const BN &x, const CurvePoint &g, const BN &order) {
    BN alpha = RandomBNLt(order);
    InternalProveWithR(x, g, order, alpha);
}

void DLogProof_V2::InternalProveWithR(const BN &x, const CurvePoint &g, const BN &order, const BN &alpha) {
    A_ = g * alpha;
    CurvePoint X = g * x;

    // c = H(G || g^alpha || g^x || UserID || OtherInfo)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    g.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    g.y().ToBytes32BE(str);
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

bool DLogProof_V2::InternalVerify(const curve::CurvePoint &X) const {
    const curve::Curve *curv = curve::GetCurveParam(X.GetCurveType());
    if(curv == nullptr) return false;

    // e = H(G || g^alpha || g^x || UserID || OtherInfo)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    curv_->g.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    curv_->g.y().ToBytes32BE(str);
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
    e = e % curv->n;

    // Verify: g^z === A * X^e
    CurvePoint left_point = curv->g * z_;
    CurvePoint right_point = A_ + X * e;
    return left_point == right_point;
}


void DLogProof_V2::Prove(const BN &x) {
    assert(curv_ != nullptr);
    BN alpha = RandomBNLt(curv_->n);
    ProveWithR(x, alpha);
}

void DLogProof_V2::ProveWithR(const BN &x, const BN &alpha) {
    assert(curv_ != nullptr);
    DLogProof_V2::InternalProveWithR(x, curv_->g, curv_->n, alpha);
}

bool DLogProof_V2::Verify(const curve::CurvePoint &X) const {
    assert(curv_ != nullptr);
    return DLogProof_V2::InternalVerify(X);
}

void DLogProof_V2::ProveEx(const BN &sk, curve::CurveType curve_type) {
    curv_ = curve::GetCurveParam(curve_type);
    assert(curv_ != nullptr);
    BN alpha = RandomBNLt(curv_->n);
    ProveWithREx(sk, alpha, curve_type);
}

void DLogProof_V2::ProveWithREx(const BN &x, const BN &alpha, curve::CurveType curve_type) {
    curv_ = curve::GetCurveParam(curve_type);
    assert(curv_ != nullptr);
    DLogProof_V2::InternalProveWithR(x, curv_->g, curv_->n, alpha);
}

bool DLogProof_V2::ToProtoObject(safeheron::proto::DLogProof_V2 &dlog_proof) const {
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

bool DLogProof_V2::FromProtoObject(const safeheron::proto::DLogProof_V2 &dlog_proof) {
    bool ok = true;
    safeheron::proto::CurvePoint point;
    // A = g^r
    point = dlog_proof.a();
    ok = A_.FromProtoObject(point);
    if (!ok) return false;

    // z
    z_ = BN::FromHexStr(dlog_proof.z());

    // Curve
    curv_ = curve::GetCurveParam(A_.GetCurveType());
    ok = (curv_ != nullptr);
    if (!ok) return false;

    return true;
}

bool DLogProof_V2::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::DLogProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool DLogProof_V2::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::DLogProof_V2 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool DLogProof_V2::ToJsonString(string &json_str) const {
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

bool DLogProof_V2::FromJsonString(const string &json_str) {
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
