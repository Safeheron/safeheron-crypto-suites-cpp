#include "pail_n_proof.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-paillier/pail.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::hash::CSHA256;
using safeheron::pail::PailPubKey;
using safeheron::pail::PailPrivKey;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;
using namespace safeheron::rand;

#define PRIME_UTIL 6370

namespace safeheron{
namespace zkp {
namespace pail {

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

void PailNProof::GenerateXs(std::vector<BN> &x_arr, const BN &N, uint32_t proof_iters) const{
    x_arr.clear();
    uint32_t i = 0;
    int n = 0;
    int j = 0;
    int N_blocks = 1 + N.BitLength() / (CSHA256::OUTPUT_SIZE * 8);
    std::unique_ptr<uint8_t[]> blocks_buf(new uint8_t[N_blocks * CSHA256::OUTPUT_SIZE]);

    memset(blocks_buf.get(), 0, N_blocks * CSHA256::OUTPUT_SIZE);
    uint8_t byte4[4];
    string N_buf;
    // N
    N.ToBytesBE(N_buf);

    while( i < proof_iters ){
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
            if(salt_.length() > 0) {
                sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
            }
            sha256.Finalize(sha256_digest);
            memcpy(blocks_buf.get() + CSHA256::OUTPUT_SIZE * j, sha256_digest, CSHA256::OUTPUT_SIZE);
        }

        BN x = BN::FromBytesBE(blocks_buf.get(), N_blocks * CSHA256::OUTPUT_SIZE);
        x = x % N;
        // x in Z_N*
        bool ok = (x > BN::ONE) && (x < N) && (x.Gcd(N) == BN::ONE);
        if (ok){
            i ++;
            x_arr.push_back(x);
        }else {
            n ++;
        }
    }
}

void PailNProof::Prove(const PailPrivKey &pail_priv, uint32_t proof_iters) {
    vector<BN> x_arr;
    BN M = pail_priv.n().InvM(pail_priv.lambda());
    GenerateXs(x_arr, pail_priv.n(), proof_iters);
    for(uint32_t i = 0; i < proof_iters; ++i){
        BN y_N = x_arr[i].PowM(M, pail_priv.n());
        y_N_arr_.push_back(y_N);
    }
}

bool PailNProof::Verify(const PailPubKey &pail_pub, uint32_t proof_iters) const {
    if(pail_pub.n().BitLength() < 2046)return false;
    if(pail_pub.n() <= 1 || pail_pub.g() <= 1)return false;
    if(pail_pub.n() + 1 != pail_pub.g())return false;

    // Check the pail N
    std::vector<int> prime_arr;
    prime_util(PRIME_UTIL, prime_arr);
    for(int p: prime_arr){
        if(pail_pub.n() % p == 0) return false;
    }

    vector<BN> x_arr;
    GenerateXs(x_arr,  pail_pub.n(), proof_iters);
    if (y_N_arr_.size() < proof_iters) return false;
    for (uint32_t i = 0; i < proof_iters; ++i) {
        if( y_N_arr_[i] <= 1 || y_N_arr_[i] >= pail_pub.n()) return false;
        if( y_N_arr_[i].Gcd(pail_pub.n()) != 1) return false;
        BN x = y_N_arr_[i].PowM(pail_pub.n(), pail_pub.n());
        if (x != x_arr[i]) {
            return false;
        }
    }
    return true;
}

bool PailNProof::ToProtoObject(safeheron::proto::PailNProof &pail_proof) const {
    safeheron::proto::CurvePoint tmp;

    for(size_t i = 0; i < y_N_arr_.size(); ++i){
        string str;
        y_N_arr_[i].ToHexStr(str);
        pail_proof.add_y_n_arr(str);
    }

    return true;
}

bool PailNProof::FromProtoObject(const safeheron::proto::PailNProof &pail_proof) {
    safeheron::proto::CurvePoint point;

    y_N_arr_.clear();
    for(int i = 0; i < pail_proof.y_n_arr_size(); ++i){
        BN y_N = BN::FromHexStr(pail_proof.y_n_arr(i));
        y_N_arr_.push_back(y_N);
    }

    return true;
}

bool PailNProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailNProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailNProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailNProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailNProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailNProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailNProof::FromJsonString(const string &json_str) {
    safeheron::proto::PailNProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
