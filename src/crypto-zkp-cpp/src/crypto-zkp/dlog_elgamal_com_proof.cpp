#include "dlog_elgamal_com_proof.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha512.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::hash::CSHA512;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;
using namespace safeheron::rand;

namespace safeheron{
namespace zkp {
namespace dlog_elgamal_com {

void DlogElGamalComProof::Prove(const DlogElGamalComStatement &statement, const DlogElGamalComWitness &witness){
    const safeheron::curve::CurvePoint &g = statement.g_;
    const safeheron::curve::CurvePoint &L = statement.L_;
    const safeheron::curve::CurvePoint &M = statement.M_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const safeheron::curve::CurvePoint &Y = statement.Y_;
    const safeheron::curve::CurvePoint &h = statement.h_;
    const safeheron::bignum::BN &q = statement.q_;

    const BN &y = witness.y_;
    const BN &lambda = witness.lambda_;

    assert(X.GetCurveType() == g.GetCurveType());

    BN alpha = RandomBNLt(q);
    BN m = RandomBNLt(q);

    // A = g^alpha
    A_ = g * alpha;
    // N = g^m * X^alpha
    N_ = g * m  + X * alpha;
    // B = h^m
    B_ = h * m;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    A_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    N_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    N_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    // z = alpha + e * lambda mod q
    z_ = ( alpha + e * lambda ) % q;
    // u = m + e * y mod q
    u_ = ( m + e * y ) % q;
}

bool DlogElGamalComProof::Verify(const DlogElGamalComStatement &statement) const {
    const safeheron::curve::CurvePoint &g = statement.g_;
    const safeheron::curve::CurvePoint &L = statement.L_;
    const safeheron::curve::CurvePoint &M = statement.M_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const safeheron::curve::CurvePoint &Y = statement.Y_;
    const safeheron::curve::CurvePoint &h = statement.h_;
    const safeheron::bignum::BN &q = statement.q_;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    A_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    N_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    N_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    bool ok = true;
    CurvePoint left_point;
    CurvePoint right_point;

    // g^z = A * L^e
    left_point = g * z_;
    right_point = A_ + L * e;
    ok = left_point == right_point;
    if(!ok) return false;

    // g^u * X^z = N * M^e
    left_point = g * u_ + X * z_;
    right_point = N_ + M * e;
    ok = left_point == right_point;
    if(!ok) return false;

    // h^u = B * Y^e
    left_point = h * u_;
    right_point = B_ + Y * e;
    ok = left_point == right_point;
    if(!ok) return false;

    return true;
}

bool DlogElGamalComProof::ToProtoObject(safeheron::proto::DlogElGamalComProof &proof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;
    string str;

    ok = A_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_a()->CopyFrom(tmp);

    ok = N_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_n()->CopyFrom(tmp);

    ok = B_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_b()->CopyFrom(tmp);

    z_.ToHexStr(str);
    proof.mutable_z()->assign(str);

    u_.ToHexStr(str);
    proof.mutable_u()->assign(str);

    return true;
}

bool DlogElGamalComProof::FromProtoObject(const safeheron::proto::DlogElGamalComProof &proof) {
    bool ok = true;

    ok = A_.FromProtoObject(proof.a());
    ok = ok && !A_.IsInfinity();
    if (!ok) return false;

    ok = N_.FromProtoObject(proof.n());
    ok = ok && !N_.IsInfinity();
    if (!ok) return false;

    ok = B_.FromProtoObject(proof.b());
    ok = ok && !B_.IsInfinity();
    if (!ok) return false;

    z_ = BN::FromHexStr(proof.z());
    ok = z_ != 0;
    if(!ok) return false;

    u_ = BN::FromHexStr(proof.u());
    ok = u_ != 0;
    if(!ok) return false;

    return true;
}

bool DlogElGamalComProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::DlogElGamalComProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool DlogElGamalComProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::DlogElGamalComProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool DlogElGamalComProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::DlogElGamalComProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool DlogElGamalComProof::FromJsonString(const string &json_str) {
    safeheron::proto::DlogElGamalComProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
