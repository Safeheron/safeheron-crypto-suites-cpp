#include "pail_dec_modulo_proof.h"
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
namespace pail {

void PailDecModuloProof::Prove(const PailDecModuloSetUp &setup, const PailDecModuloStatement &statement, const PailDecModuloWitness &witness){
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &q = statement.q_;
    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &C = statement.C_;
    const BN &x = statement.x_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    const BN &y = witness.y_;
    const BN &rho = witness.rho_;

    // limitation
    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);
    // 2^l * N_tilde
    const BN limit_mu = (BN::ONE << l) * N_tilde;
    // 2^(l + varepsilon) * N_tilde
    const BN limit_v = limit_alpha * N_tilde;

    // random
    BN alpha = RandomNegBNInSymInterval(limit_alpha);
    BN mu = RandomNegBNInSymInterval(limit_mu);
    BN v = RandomNegBNInSymInterval(limit_v);
    BN r = RandomBNLtCoPrime(N0);

    // S = s^y * t^mu mod N_tilde
    S_ = ( s.PowM(y, N_tilde) * t.PowM(mu, N_tilde) ) % N_tilde;
    // T = s^alpha * t^v mod N_tilde
    T_ = ( s.PowM(alpha, N_tilde) * t.PowM(v, N_tilde) ) % N_tilde;
    // A = (1 + N0)^alpha * r^N0 mod N0^2
    A_ = ( (N0 * alpha + 1) * r.PowM(N0, N0Sqr) ) % N0Sqr;
    // gamma = alpha  mod q
    gamma_ = alpha % q;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    q.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    x.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    gamma_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    // z1 = alpha + e * y
    z1_ = alpha + e * y;
    // z2 = v + e * mu
    z2_ = v + e * mu;
    // w = r * rho^e
    w_ = ( r * rho.PowM(e, N0Sqr) ) % N0Sqr;
}

bool PailDecModuloProof::Verify(const PailDecModuloSetUp &setup, const PailDecModuloStatement &statement) const {
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &q = statement.q_;
    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &C = statement.C_;
    const BN &x = statement.x_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    if(N_tilde.BitLength() < 2047) return false;
    if(S_ % N_tilde == 0) return false;
    if(T_ % N_tilde == 0) return false;
    if(A_.Gcd(N0) != BN::ONE) return false;
    if(w_.Gcd(N0) != BN::ONE) return false;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    q.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    x.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    gamma_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    bool ok = true;
    BN left_num;
    BN right_num;

    // (1 + N0)^z1 * w^N0 = A * C^e mod N0^2
    left_num = ( (N0 * z1_ + 1) * w_.PowM(N0, N0Sqr) ) % N0Sqr;
    right_num = ( C.PowM(e, N0Sqr) * A_ ) % N0Sqr;
    ok = left_num == right_num;
    if(!ok) return false;

    // z1 = r + e * x    mod q
    left_num = z1_ % q;
    right_num = ( gamma_ + e * x ) % q;
    ok = left_num == right_num;
    if(!ok) return false;

    // s^z1 * t^z2 = T * S^e    mod N_tilde
    left_num = ( s.PowM(z1_, N_tilde) * t.PowM(z2_, N_tilde) ) % N_tilde;
    right_num = ( T_ *  S_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    return true;
}

bool PailDecModuloProof::ToProtoObject(safeheron::proto::PailDecModuloProof &proof) const {
    string str;

    bool ok = true;

    S_.ToHexStr(str);
    proof.mutable_s()->assign(str);

    T_.ToHexStr(str);
    proof.mutable_t()->assign(str);

    A_.ToHexStr(str);
    proof.mutable_a()->assign(str);

    gamma_.ToHexStr(str);
    proof.mutable_gamma()->assign(str);

    z1_.ToHexStr(str);
    proof.mutable_z1()->assign(str);

    z2_.ToHexStr(str);
    proof.mutable_z2()->assign(str);

    w_.ToHexStr(str);
    proof.mutable_w()->assign(str);

    return true;
}

bool PailDecModuloProof::FromProtoObject(const safeheron::proto::PailDecModuloProof &proof) {
    bool ok = true;

    S_ = BN::FromHexStr(proof.s());
    ok = S_ != 0;
    if(!ok) return false;

    T_ = BN::FromHexStr(proof.t());
    ok = T_ != 0;
    if(!ok) return false;

    A_ = BN::FromHexStr(proof.a());
    ok = A_ != 0;
    if(!ok) return false;

    gamma_ = BN::FromHexStr(proof.gamma());
    ok = gamma_ != 0;
    if(!ok) return false;

    z1_ = BN::FromHexStr(proof.z1());
    ok = z1_ != 0;
    if(!ok) return false;

    z2_ = BN::FromHexStr(proof.z2());
    ok = z2_ != 0;
    if(!ok) return false;

    w_ = BN::FromHexStr(proof.w());
    ok = w_ != 0;
    if(!ok) return false;

    return true;
}

bool PailDecModuloProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailDecModuloProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailDecModuloProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailDecModuloProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailDecModuloProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailDecModuloProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailDecModuloProof::FromJsonString(const string &json_str) {
    safeheron::proto::PailDecModuloProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
