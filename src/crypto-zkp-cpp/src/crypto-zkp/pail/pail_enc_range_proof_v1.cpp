#include "pail_enc_range_proof_v1.h"
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
namespace pail {

void PailEncRangeProof_V1::Prove(const PailEncRangeSetUp_V1 &setup, const PailEncRangeStatement_V1 &statement, const PailEncRangeWitness_V1 &witness){
    const BN &N_tilde = setup.N_tilde_;
    const BN &h1 = setup.h1_;
    const BN &h2 = setup.h2_;

    const BN &c = statement.c_;
    const BN &N = statement.N_;
    const BN &N2 = statement.N2_;
    const BN &q = statement.q_;

    const BN &x = witness.x_;
    const BN &r = witness.r_;

    BN q2 = q * q;
    BN q3 = q * q2;
    BN q_N_tilde = q * N_tilde;
    BN q3_N_tilde = q2 * q_N_tilde;

    // random
    BN alpha = RandomBNLt(q3);
    BN beta = RandomBNLtGcd(N);
    BN gamma = RandomBNLt(q3_N_tilde);
    BN rho = RandomBNLt(q_N_tilde);

    // z = h1^m * h2^rho mod N_tilde
    z_ = ( h1.PowM(x, N_tilde) * h2.PowM(rho, N_tilde) ) % N_tilde;
    // u = Gamma^alpha * beta^N mod N^2
    //   = ( (1+N).PowM(alpha, N2) * beta.PowM(N, N2) ) % N2;
    //   = ( (1 + alpha * N) % N2 * beta.PowM(N, N2) ) % N2;
    u_ = ( (N * alpha + 1) % N2 * beta.PowM(N, N2) ) % N2;
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
    s1_ = e * x + alpha;
    s2_ = e * rho + gamma;
}

bool PailEncRangeProof_V1::Verify(const PailEncRangeSetUp_V1 &setup, const PailEncRangeStatement_V1 &statement) const {
    const BN &N_tilde = setup.N_tilde_;
    const BN &h1 = setup.h1_;
    const BN &h2 = setup.h2_;

    const BN &c = statement.c_;
    const BN &N = statement.N_;
    const BN &N2 = statement.N2_;
    const BN &q = statement.q_;

    BN q2 = q * q;
    BN q3 = q * q2;

    if(N_tilde.BitLength() < 2047) return false;
    if(N.BitLength() < 2047) return false;

    if(z_.Gcd(N_tilde) != BN::ONE) return false;
    if(u_.Gcd(N) != BN::ONE) return false;
    if(w_.Gcd(N_tilde) != BN::ONE) return false;
    if(s_.Gcd(N) != BN::ONE) return false;

    if(s1_ < (BN::ZERO - q3) || s1_ > q3)return false;

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

    // u = Gamma^s1 * s^N * c^(-e) mod N^2 = Enc(s1, s) (+) c (*) (-e)
    //   = (1 + N * s1) % N2 * s^N * c^(-e) mod N^2 = Enc(N, s1, s) (+) c (*) (-e)
    BN u = ( (N * s1_ + 1) % N2 * s_.PowM(N, N2) * c.PowM(e, N2).InvM(N2) ) % N2;
    // w = h1^s1 * h2^s2 * z^(-e) mod N_tilde
    BN w = ( h1.PowM(s1_, N_tilde) * h2.PowM(s2_, N_tilde) * z_.PowM(e, N_tilde).InvM(N_tilde) ) % N_tilde;
    return (u == u_) && (w == w_);
}

bool PailEncRangeProof_V1::ToProtoObject(safeheron::proto::PailEncRangeProof_V1 &proof) const {
    string str;
    z_.ToHexStr(str);
    proof.mutable_z()->assign(str);

    u_.ToHexStr(str);
    proof.mutable_u()->assign(str);

    w_.ToHexStr(str);
    proof.mutable_w()->assign(str);

    s_.ToHexStr(str);
    proof.mutable_s()->assign(str);

    s1_.ToHexStr(str);
    proof.mutable_s1()->assign(str);

    s2_.ToHexStr(str);
    proof.mutable_s2()->assign(str);

    return true;
}

bool PailEncRangeProof_V1::FromProtoObject(const safeheron::proto::PailEncRangeProof_V1 &proof) {
    bool ok = true;

    z_ = BN::FromHexStr(proof.z());
    ok = z_ != 0;
    if(!ok) return false;

    u_ = BN::FromHexStr(proof.u());
    ok = u_ != 0;
    if(!ok) return false;

    w_ = BN::FromHexStr(proof.w());
    ok = w_ != 0;
    if(!ok) return false;

    s_ = BN::FromHexStr(proof.s());
    ok = s_ != 0;
    if(!ok) return false;

    s1_ = BN::FromHexStr(proof.s1());
    ok = s1_ != 0;
    if(!ok) return false;

    s2_ = BN::FromHexStr(proof.s2());
    ok = s2_ != 0;
    if(!ok) return false;

    return true;
}

bool PailEncRangeProof_V1::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailEncRangeProof_V1 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailEncRangeProof_V1::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailEncRangeProof_V1 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailEncRangeProof_V1::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailEncRangeProof_V1 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailEncRangeProof_V1::FromJsonString(const string &json_str) {
    safeheron::proto::PailEncRangeProof_V1 proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
