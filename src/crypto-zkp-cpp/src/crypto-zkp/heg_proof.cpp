#include "heg_proof.h"
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
namespace heg {

void HegProof::Prove(const HomoElGamalStatement &delta, const HomoElGamalWitness &witness) {
    BN s1 = RandomBN(256);
    BN s2 = RandomBN(256);
    ProveWithR(delta, witness, s1, s2);
}

void
HegProof::ProveWithR(const HomoElGamalStatement &delta, const HomoElGamalWitness &witness, const BN &s1, const BN &s2) {
    // T = H^s1 + Y^s2
    curve::CurvePoint A1 = delta.H_ * s1;
    curve::CurvePoint A2 = delta.Y_ * s2;
    curve::CurvePoint A3 = delta.G_ * s2;
    curve::CurvePoint T = A1 + A2;

    const curve::Curve * curve = curve::GetCurveParam(delta.H_.GetCurveType());

    // e = H(T || A3 || G || H || Y || D || E)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    T.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A3.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.G_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.H_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.Y_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.D_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.E_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);

    BN e = BN::FromBytesBE(sha256_digest, 32);

    // z1 = s1 + x * e mod q
    BN z1 = s1;
    if (witness.x_ != 0) {
        z1 = (s1 + witness.x_ * e) % curve->n;
    }

    // z1 = s2 + r * e mod q
    BN z2 = (s2 + witness.r_ * e) % curve->n;

    T_ = T;
    A3_ = A3;
    z1_ = z1;
    z2_ = z2;
}

bool HegProof::Verify(const HomoElGamalStatement &delta) const {
    // T = H^s1 + Y^s2
    // A3 = G^s2
    // z1 = s1 + x * e mod q
    // z2 = s2 + r * e mod q

    // e = H(T || A3 || G || H || Y || D || E)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    T_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A3_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.G_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.H_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.Y_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.D_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    delta.E_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, 32);

    // H^z1 + Y^z2
    curve::CurvePoint z1H_plus_z2Y = delta.H_ * z1_ + delta.Y_ * z2_;
    // H^s1 + Y^s2 + D^e
    curve::CurvePoint T_plus_eD = T_ + delta.D_ * e;
    // G^z2
    curve::CurvePoint z2G = delta.G_ * z2_;
    // A3 + E^e
    curve::CurvePoint A3_plus_eE = A3_ + delta.E_ * e;
    return (z1H_plus_z2Y == T_plus_eD) && (z2G == A3_plus_eE);
}

bool HegProof::ToProtoObject(safeheron::proto::HegProof &hegProof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;

    // T
    ok = T_.ToProtoObject(tmp);
    if (!ok) return false;
    hegProof.mutable_t()->CopyFrom(tmp);

    // A3
    ok = A3_.ToProtoObject(tmp);
    if (!ok) return false;
    hegProof.mutable_a3()->CopyFrom(tmp);

    // z1
    std::string str;
    z1_.ToHexStr(str);
    hegProof.set_z1(str);

    // res
    z2_.ToHexStr(str);
    hegProof.set_z2(str);

    return true;
}

bool HegProof::FromProtoObject(const safeheron::proto::HegProof &hegProof) {
    bool ok = true;
    safeheron::proto::CurvePoint point;
    // T
    point = hegProof.t();
    ok = T_.FromProtoObject(point);
    ok = ok && !T_.IsInfinity();
    if (!ok) return false;

    // A3
    point = hegProof.a3();
    ok = A3_.FromProtoObject(point);
    ok = ok && !A3_.IsInfinity();
    if (!ok) return false;

    // z1
    z1_ = BN::FromHexStr(hegProof.z1());
    ok = (z1_ != 0);
    if (!ok) return false;

    // z2
    z2_ = BN::FromHexStr(hegProof.z2());
    ok = (z2_ != 0);
    if (!ok) return false;

    return true;
}

bool HegProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::HegProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool HegProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::HegProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool HegProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::HegProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool HegProof::FromJsonString(const string &json_str) {
    safeheron::proto::HegProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
