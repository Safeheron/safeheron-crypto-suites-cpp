#include "range_proof.h"
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
namespace range_proof {

void AliceRangeProof::Prove(const BN &q, const BN &N, const BN &g, const BN &N_tilde, const BN &h1, const BN &h2, const BN &c, const BN &m, const BN &r) {
    BN q2 = q * q;
    BN q3 = q * q2;
    BN q_N_tilde = q * N_tilde;
    BN q3_N_tilde = q2 * q_N_tilde;
    BN N2 = N * N;

    // random
    BN alpha = RandomBNLt(q3);
    BN beta = RandomBNLtGcd(N);
    BN gamma = RandomBNLt(q3_N_tilde);
    BN rho = RandomBNLt(q_N_tilde);

    // z = h1^m * h2^rho mod N_tilde
    z_ = ( h1.PowM(m, N_tilde) * h2.PowM(rho, N_tilde) ) % N_tilde;
    // u = g^alpha * beta^N mod N_tilde^2
    u_ = ( g.PowM(alpha, N2) * beta.PowM(N, N2) ) % N2;
    // w = h1^alpha * h2^gamma mod N_tilde
    w_ = ( h1.PowM(alpha, N_tilde) * h2.PowM(gamma, N_tilde) ) % N_tilde;

    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    N.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    c.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    z_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    u_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    w_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));
    e = e % q;

    s_ = ( r.PowM(e, N) * beta ) % N;
    s1_ = e * m + alpha;
    s2_ = e * rho + gamma;
}

bool AliceRangeProof::Verify(const BN &q, const BN &N, const BN &g, const BN &N_tilde, const BN &h1, const BN &h2, const BN &c) const {
    BN q2 = q * q;
    BN q3 = q * q2;
    BN q_N_tilde = q * N_tilde;
    BN q3_N_tilde = q2 * q_N_tilde;
    BN N2 = N * N;

    if(N_tilde.BitLength() < 2047) return false;

    if(z_ % N_tilde == 0) return false;
    if(u_.Gcd(N) != BN::ONE) return false;
    if(w_ % N_tilde == 0) return false;
    if(s_.Gcd(N) != BN::ONE) return false;

    if(s1_ > q3)return false;

    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    N.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    c.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    z_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    u_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    w_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));
    e = e % q;

    // u = g^s1 * s^N * c^(-e) mod N
    BN u = ( g.PowM(s1_, N2) * s_.PowM(N, N2) * c.PowM(e, N2).InvM(N2) ) % N2;
    // w = h1^s1 * h2^s2 * z^(-e) mod N_tilde
    BN w = ( h1.PowM(s1_, N_tilde) * h2.PowM(s2_, N_tilde) * z_.PowM(e, N_tilde).InvM(N_tilde) ) % N_tilde;
    return (u == u_) && (w == w_);
}

bool AliceRangeProof::ToProtoObject(safeheron::proto::AliceRangeProof &alice_range_proof) const {
    string str;
    z_.ToHexStr(str);
    alice_range_proof.mutable_z()->assign(str);

    u_.ToHexStr(str);
    alice_range_proof.mutable_u()->assign(str);

    w_.ToHexStr(str);
    alice_range_proof.mutable_w()->assign(str);

    s_.ToHexStr(str);
    alice_range_proof.mutable_s()->assign(str);

    s1_.ToHexStr(str);
    alice_range_proof.mutable_s1()->assign(str);

    s2_.ToHexStr(str);
    alice_range_proof.mutable_s2()->assign(str);

    return true;
}

bool AliceRangeProof::FromProtoObject(const safeheron::proto::AliceRangeProof &alice_range_proof) {
    bool ok = true;

    z_ = BN::FromHexStr(alice_range_proof.z());
    ok = z_ != 0;
    if(!ok) return false;

    u_ = BN::FromHexStr(alice_range_proof.u());
    ok = u_ != 0;
    if(!ok) return false;

    w_ = BN::FromHexStr(alice_range_proof.w());
    ok = w_ != 0;
    if(!ok) return false;

    s_ = BN::FromHexStr(alice_range_proof.s());
    ok = s_ != 0;
    if(!ok) return false;

    s1_ = BN::FromHexStr(alice_range_proof.s1());
    ok = s1_ != 0;
    if(!ok) return false;

    s2_ = BN::FromHexStr(alice_range_proof.s2());
    ok = s2_ != 0;
    if(!ok) return false;

    return true;
}

bool AliceRangeProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::AliceRangeProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool AliceRangeProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::AliceRangeProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool AliceRangeProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::AliceRangeProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool AliceRangeProof::FromJsonString(const string &json_str) {
    safeheron::proto::AliceRangeProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
