#include "pail_blum_modulus_proof.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

#define PRIME_UTIL 6370

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

const int ITERATIONS_BlumInt_Proof = 128;
const int ITERATIONS_PailN_Proof = 11;

static void prime_util(int n, std::vector<int> &prime_arr){
    assert(n > 0);
    prime_arr.clear();
    if(n < 2) return;
    for(int i = 3; i <= n; i++){
        bool is_prime = true;
        for(int p: prime_arr){
            if(p * p >= i) {
                break;
            }
            if(i % p == 0) {
                is_prime = false;
                break;
            }
        }
        if(is_prime)prime_arr.push_back(i);
    }
}

static void uint_to_byte4(uint8_t buf[4], unsigned int ui){
    // Big endian
    buf[3] = ui & 0x000000ff;
    buf[2] = (ui & 0x0000ff00) >> 8;
    buf[1] = (ui & 0x00ff0000) >> 16;
    buf[0] = (ui & 0xff000000) >> 24;

}

void PailBlumModulusProof::GenerateYs(std::vector<safeheron::bignum::BN> &x_arr, const safeheron::bignum::BN &N, const safeheron::bignum::BN &w, uint32_t proof_iters) const{
    x_arr.clear();
    uint32_t i = 0;
    int n = 0;
    int j = 0;
    int N_blocks = 1 + N.BitLength() / (CSHA256::OUTPUT_SIZE * 8);
    std::unique_ptr<uint8_t[]> blocks_buf(new uint8_t[N_blocks * CSHA256::OUTPUT_SIZE]);

    memset(blocks_buf.get(), 0, N_blocks * CSHA256::OUTPUT_SIZE);
    uint8_t byte4[4];
    string N_buf;
    string w_buf;

    // N
    N.ToBytesBE(N_buf);
    // w
    w.ToBytesBE(w_buf);

    for( i = 0; i < ITERATIONS_BlumInt_Proof; ++i ){
        for( j = 0; j < N_blocks; ++j ){
            // digest = H(i || j || n || index || point_x || point_y || N)
            CSHA256 sha256;
            uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
            string str;
            // i
            uint_to_byte4(byte4, i);
            sha256.Write( byte4, 4);
            // j
            uint_to_byte4(byte4, j);
            sha256.Write( byte4, 4);
            // n
            uint_to_byte4(byte4, n);
            sha256.Write( byte4, 4);
            // N
            sha256.Write((const uint8_t *)(N_buf.c_str()), N_buf.length());
            // w
            sha256.Write((const uint8_t *)(w_buf.c_str()), w_buf.length());
            if(salt_.length() > 0) {
                sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
            }
            sha256.Finalize(sha256_digest);
            memcpy(blocks_buf.get() + CSHA256::OUTPUT_SIZE * j, sha256_digest, CSHA256::OUTPUT_SIZE);
        }

        BN x = BN::FromBytesBE(blocks_buf.get(), N_blocks * CSHA256::OUTPUT_SIZE);
        x = x % N;
        x_arr.push_back(x);
    }
}

bool PailBlumModulusProof::GetQuarticSqrt(const safeheron::bignum::BN &N, const safeheron::bignum::BN &p, const safeheron::bignum::BN &q, const safeheron::bignum::BN &p_inv, const safeheron::bignum::BN &q_inv, const safeheron::bignum::BN &w, const safeheron::bignum::BN &r, safeheron::bignum::BN &root, int32_t &a, int32_t &b) {
    BN a1;
    BN a2;
    bool flag_1 = false;
    bool flag_2 = false;
    BN quadratic_root_1;
    BN quadratic_root_2;

    // one of {r, -1 * r, w * r, -1 * w * r } is a quadratic residue
    std::vector<BN> r_arr;
    r_arr.push_back(r);                 // (a, b) = (0, 0)
    r_arr.push_back(r * BN(-1));     // (a, b) = (1, 0)
    r_arr.push_back(r * w);             // (a, b) = (0, 1)
    r_arr.push_back(r * w * BN(-1)); // (a, b) = (1, 1)

    // Group Zpq is isomorphic to group Zp * Zq
    std::vector<BN> a1_arr;
    std::vector<BN> a2_arr;
    for (size_t i = 0; i < r_arr.size(); ++i) {
        a1_arr.push_back(r_arr[i] % p);
        a2_arr.push_back(r_arr[i] % q);
    }

    for (size_t i = 0; i < a1_arr.size(); ++i) {
        flag_1 = a1_arr[i].ExistSqrtM(p);
        if(!flag_1) continue;
        flag_2 = a2_arr[i].ExistSqrtM(q);
        if(!flag_2) continue;
        quadratic_root_1 = a1_arr[i].SqrtM(p);
        quadratic_root_2 = a2_arr[i].SqrtM(q);
        a = (i & 0x01) ? 1 : 0;
        b = (i & 0x02) ? 1 : 0;
        break;
    }
    if(!flag_2) return false;

    // Group Zpq is isomorphic to group Zp * Zq
    // (a1, a2) is an element in Zp * Zq.
    // if (a1, a2) is a quadratic residue in Zp * Zq, then one of {(a1, a2), (-a1, a2), (a1, -a2), (-a1, -a2)} is a quartic residue.
    a1_arr.clear();
    a2_arr.clear();
    a1_arr.push_back(quadratic_root_1);
    a2_arr.push_back(quadratic_root_2);
    a1_arr.push_back(quadratic_root_1 * BN(-1));
    a2_arr.push_back(quadratic_root_2);
    a1_arr.push_back(quadratic_root_1);
    a2_arr.push_back(quadratic_root_2 * BN(-1));
    a1_arr.push_back(quadratic_root_1 * BN(-1));
    a2_arr.push_back(quadratic_root_2 * BN(-1));

    for (size_t i = 0; i < a1_arr.size(); ++i) {
        flag_1 = a1_arr[i].ExistSqrtM(p);
        if(!flag_1) continue;
        flag_2 = a2_arr[i].ExistSqrtM(q);
        if(!flag_2) continue;
        quadratic_root_1 = a1_arr[i].SqrtM(p);
        quadratic_root_2 = a2_arr[i].SqrtM(q);
        root = (quadratic_root_1 * q_inv * q + quadratic_root_2 * p_inv * p) % N;
        return true;
    }

    return false;
}

bool PailBlumModulusProof::Prove(const safeheron::bignum::BN &N, const safeheron::bignum::BN &p, const safeheron::bignum::BN &q) {
    if(N != p * q) return false;

    w_ = RandomBNLt(N);
    while (BN::JacobiSymbol(w_, N) != -1){
        w_ = RandomBNLt(N);
    }

    std::vector<BN> y_arr;
    GenerateYs(y_arr, N, w_, ITERATIONS_BlumInt_Proof);

    for(int i = 0; i < ITERATIONS_BlumInt_Proof; ++i){
        BN root;
        int32_t a, b;
        bool ok = GetQuarticSqrt(N, p, q, p.InvM(q), q.InvM(p), w_, y_arr[i], root, a, b);
        if(!ok) return false;
        x_arr_.push_back(root);
        a_arr_.push_back(a);
        b_arr_.push_back(b);
    }

    BN lambda = (p - 1) * (q - 1);
    BN N_inv = N.InvM(lambda);
    for(uint32_t i = 0; i < ITERATIONS_PailN_Proof; ++i){
        BN z = y_arr[i].PowM(N_inv, N);
        z_arr_.push_back(z);
    }
    return true;
}

bool PailBlumModulusProof::Verify(const BN &N) const {
    if( (x_arr_.size() < ITERATIONS_BlumInt_Proof) || (a_arr_.size() < ITERATIONS_BlumInt_Proof)  || (b_arr_.size() < ITERATIONS_BlumInt_Proof)  || (z_arr_.size() < ITERATIONS_PailN_Proof) ) return false;

    if(N <= 1 || N.BitLength() < 2046) return false;
    if(w_ <= 0 || w_ >= N) return false;
    if(BN::JacobiSymbol(w_, N) != -1) return false;

    std::vector<BN> y_arr;
    GenerateYs(y_arr, N, w_, ITERATIONS_BlumInt_Proof);

    for(int i = 0; i < ITERATIONS_BlumInt_Proof; ++i){
        BN expect_y_prime = x_arr_[i].PowM(BN(4), N);
        BN y_prime = (y_arr[i] * (a_arr_[i] ? BN::MINUS_ONE : BN::ONE) * (b_arr_[i] ? w_ : BN::ONE)) % N;
        if(expect_y_prime != y_prime) return false;
    }

    // Check the pail N
    std::vector<int> prime_arr;
    prime_util(PRIME_UTIL, prime_arr);
    for(int p: prime_arr){
        if(N % p == 0) return false;
    }

    for (uint32_t i = 0; i < ITERATIONS_PailN_Proof; ++i) {
        if(z_arr_[i] <= 1 || z_arr_[i] >= N) return false;
        if(z_arr_[i].Gcd(N) != 1) return false;
        BN z = z_arr_[i].PowM(N, N);
        if (z != y_arr[i]) return false;
    }
    return true;
}

bool PailBlumModulusProof::ToProtoObject(safeheron::proto::PailBlumModulusProof &proof) const {
    string str;

    proof.clear_x_arr();
    for(size_t i = 0; i < x_arr_.size(); ++i){
        string str;
        x_arr_[i].ToHexStr(str);
        proof.add_x_arr(str);
    }

    proof.clear_a_arr();
    for(size_t i = 0; i < a_arr_.size(); ++i){
        proof.add_a_arr(a_arr_[i]);
    }

    proof.clear_b_arr();
    for(size_t i = 0; i < b_arr_.size(); ++i){
        proof.add_b_arr(b_arr_[i]);
    }

    proof.clear_z_arr();
    for(size_t i = 0; i < z_arr_.size(); ++i){
        z_arr_[i].ToHexStr(str);
        proof.add_z_arr(str);
    }

    w_.ToHexStr(str);
    proof.set_w(str);

    return true;
}

bool PailBlumModulusProof::FromProtoObject(const safeheron::proto::PailBlumModulusProof &proof) {
    x_arr_.clear();
    a_arr_.clear();
    b_arr_.clear();
    z_arr_.clear();

    for(int i = 0; i < proof.x_arr_size(); ++i){
        BN alpha = BN::FromHexStr(proof.x_arr(i));
        x_arr_.push_back(alpha);
    }

    for(int i = 0; i < proof.a_arr_size(); ++i){
        a_arr_.push_back(proof.a_arr(i));
    }

    for(int i = 0; i < proof.b_arr_size(); ++i){
        b_arr_.push_back(proof.b_arr(i));
    }

    for(int i = 0; i < proof.z_arr_size(); ++i){
        BN t = BN::FromHexStr(proof.z_arr(i));
        z_arr_.push_back(t);
    }

    w_ = BN::FromHexStr(proof.w());

    return true;
}

bool PailBlumModulusProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailBlumModulusProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailBlumModulusProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailBlumModulusProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailBlumModulusProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailBlumModulusProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailBlumModulusProof::FromJsonString(const string &json_str) {
    safeheron::proto::PailBlumModulusProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
