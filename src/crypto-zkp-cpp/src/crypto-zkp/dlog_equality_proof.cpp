#include "dlog_equality_proof.h"
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
namespace dlog_equality {

void DlogEqualityProof::Prove(const DlogEqualityStatement &statement, const BN &x){
    const safeheron::curve::CurvePoint &g = statement.g_;
    const safeheron::curve::CurvePoint &h = statement.h_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const safeheron::curve::CurvePoint &Y = statement.Y_;
    const safeheron::bignum::BN &q = statement.q_;

    assert(X.GetCurveType() == g.GetCurveType());

    BN alpha = RandomBNLt(q);

    // A = g^alpha
    A_ = g * alpha;
    // B = h^alpha
    B_ = h * alpha;

    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    h.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    h.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Y.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Y.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B_.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B_.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));
    e = e % q;

    // z = alpha + e * x mod q
    z_ = ( alpha + e * x ) % q;
}

bool DlogEqualityProof::Verify(const DlogEqualityStatement &statement) const {
    const safeheron::curve::CurvePoint &g = statement.g_;
    const safeheron::curve::CurvePoint &h = statement.h_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const safeheron::curve::CurvePoint &Y = statement.Y_;
    const safeheron::bignum::BN &q = statement.q_;

    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    h.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    h.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    X.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Y.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Y.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A_.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B_.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B_.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));
    e = e % q;

    bool ok = true;
    CurvePoint left_point;
    CurvePoint right_point;

    // g^z = A * X^e
    left_point = g * z_;
    right_point = A_ + X * e;
    ok = left_point == right_point;
    if(!ok) return false;

    // h^z = B * Y^e
    left_point = h * z_;
    right_point = B_ + Y * e;
    ok = left_point == right_point;
    if(!ok) return false;

    return true;
}

bool DlogEqualityProof::ToProtoObject(safeheron::proto::DlogEqualityProof &proof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;
    string str;

    ok = A_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_a()->CopyFrom(tmp);

    ok = B_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_b()->CopyFrom(tmp);

    z_.ToHexStr(str);
    proof.mutable_z()->assign(str);

    return true;
}

bool DlogEqualityProof::FromProtoObject(const safeheron::proto::DlogEqualityProof &proof) {
    bool ok = true;

    ok = A_.FromProtoObject(proof.a());
    ok = ok && !A_.IsInfinity();
    if (!ok) return false;

    ok = B_.FromProtoObject(proof.b());
    ok = ok && !B_.IsInfinity();
    if (!ok) return false;

    z_ = BN::FromHexStr(proof.z());
    ok = z_ != 0;
    if(!ok) return false;

    return true;
}

bool DlogEqualityProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::DlogEqualityProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool DlogEqualityProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::DlogEqualityProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool DlogEqualityProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::DlogEqualityProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool DlogEqualityProof::FromJsonString(const string &json_str) {
    safeheron::proto::DlogEqualityProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
