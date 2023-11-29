#include "bip32_ecdsa.h"
#include "../crypto-curve/curve.h"
#include "../crypto-hash/hmac_sha512.h"
#include "../crypto-hash/sha256.h"
#include "../crypto-hash/ripemd160.h"
#include "../crypto-encode/base58.h"
#include "../exception/located_exception.h"
#include "hd_path.h"
#include "bip32.h"
#include "util.h"
#include "memzero.h"

#define memzero crypto_bip32_memzero

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::bip32::HDPath;
using safeheron::bip32::HDKey;
using safeheron::bip32::Bip32Version;
using safeheron::hash::CHMAC_SHA512;
using safeheron::hash::CSHA256;
using safeheron::hash::CRIPEMD160;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

namespace safeheron{
namespace bip32 {
namespace _ecdsa {

const char * DEFAULT_KEY = "Bitcoin seed";

bool is_valid_curve_type(CurveType curve_type){
    return (curve_type == CurveType::SECP256K1) || (curve_type == CurveType::P256);
}

int hdnode_from_seed(const uint8_t *seed, int seed_len, safeheron::curve::CurveType curve_type,
                     HDNode *out) {
    assert(is_valid_curve_type(static_cast<CurveType>(curve_type)));
    uint8_t I[32 + 32];

    CHMAC_SHA512 hmac((const uint8_t *)DEFAULT_KEY, strlen(DEFAULT_KEY));
    hmac.Write(seed, seed_len);
    hmac.Finalize(I);

    const Curve *curv = curve::GetCurveParam(curve_type);
    BN a;
    a = BN::FromBytesBE(I, 32);
    if ( (a == 0) || (a >= curv->n) ){  // Invalid
        return 0;
    }

    memzero(out, sizeof(HDNode));
    out->depth_ = 0;
    out->child_num_ = 0;
    out->curve_type_ = static_cast<uint32_t>(curve_type);
    memcpy(out->private_key_, I, 32);
    memcpy(out->chain_code_, I + 32, 32);
    memzero(out->public_key_, sizeof(out->public_key_));
    memzero(I, 64);
    return 1;
}

int hdnode_from_xprv(uint32_t depth, uint32_t child_num,
                      const uint8_t *chain_code, const uint8_t *private_key,
                      safeheron::curve::CurveType curve_type, HDNode *out) {
    assert(is_valid_curve_type(static_cast<CurveType>(curve_type)));
    const Curve *curv = curve::GetCurveParam(curve_type);
    BN a;
    a = BN::FromBytesBE(private_key, 32);
    if ( (a == 0) || (a >= curv->n) ){  // Invalid index
        return 0;
    }
    out->curve_type_ = static_cast<uint32_t>(curve_type);
    out->depth_ = depth;
    out->child_num_ = child_num;
    memcpy(out->chain_code_, chain_code, 32);
    memcpy(out->private_key_, private_key, 32);
    memzero(out->public_key_, sizeof(out->public_key_));
    memzero(out->private_key_extension_, sizeof(out->private_key_extension_));
    return 1;
}

int hdnode_from_xpub(uint32_t depth, uint32_t child_num,
                     const uint8_t *chain_code, const uint8_t *public_key,
                     safeheron::curve::CurveType curve_type, HDNode *out) {
    assert(is_valid_curve_type(static_cast<CurveType>(curve_type)));
    if ( public_key[0] != 0x02 && public_key[0] != 0x03 ) {  // invalid pubkey
        return 0;
    }
    CurvePoint p;
    if(!p.DecodeCompressed(public_key, curve_type)) return 0;
    out->depth_ = depth;
    out->child_num_ = child_num;
    out->curve_type_ = static_cast<uint32_t>(curve_type);
    memcpy(out->chain_code_, chain_code, 32);
    memcpy(out->public_key_, public_key, 33);
    memzero(out->private_key_, 32);
    memzero(out->private_key_extension_, 32);
    return 1;
}

uint32_t hdnode_fingerprint(const HDNode *node) {
    assert(is_valid_curve_type(static_cast<CurveType>(node->curve_type_)));
    uint32_t fingerprint = 0;

    HDNode t_node = *node;
    hdnode_fill_public_key(&t_node);

    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE] = {0};
    uint8_t digest[CRIPEMD160::OUTPUT_SIZE] = {0};
    CSHA256().Write(t_node.public_key_, 33).Finalize(sha256_digest);
    CRIPEMD160().Write(sha256_digest, CSHA256::OUTPUT_SIZE).Finalize(digest);

    fingerprint = ((uint32_t)digest[0] << 24) + (digest[1] << 16) +
                  (digest[2] << 8) + digest[3];
    memzero(sha256_digest, sizeof(sha256_digest));
    memzero(digest, sizeof(digest));
    memzero(&t_node, sizeof(HDNode));
    return fingerprint;
}

void hdnode_fill_public_key(HDNode *node) {
    assert(is_valid_curve_type(static_cast<CurveType>(node->curve_type_)));
    uint32_t has_pub = 0;
    for(int i = 0; i < 33; i++){
        has_pub = has_pub | node->public_key_[i];
    }
    if (has_pub != 0) return;
    const Curve *curv = curve::GetCurveParam(static_cast<CurveType>(node->curve_type_));
    BN x = BN::FromBytesBE(node->private_key_, 32);
    CurvePoint point = curv->g * x;
    point.EncodeCompressed(node->public_key_);
}

int hdnode_private_ckd(HDNode *inout, uint32_t i) {
    assert(is_valid_curve_type(static_cast<CurveType>(inout->curve_type_)));
    uint8_t data[1 + 32 + 4];
    uint8_t I[32 + 32];
    BN a, b;
    const Curve *curv = curve::GetCurveParam(static_cast<CurveType>(inout->curve_type_));

    if (i & 0x80000000) {  // private derivation, hardened derivation
        data[0] = 0;
        memcpy(data + 1, inout->private_key_, 32);
    } else {  // public derivation, normal(no hardened) derivation
        BN x = BN::FromBytesBE(inout->private_key_, 32);
        CurvePoint point = curv->g * x;
        point.EncodeCompressed(data);
    }
    write_be(data + 33, i);

    a = BN::FromBytesBE(inout->private_key_, 32);

    CHMAC_SHA512(inout->chain_code_, 32)
            .Write(data, sizeof(data))
            .Finalize(I);

    while (true) {
        bool failed = false;
        b = BN::FromBytesBE(I, 32);
        // In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid
        if (b >= curv->n) {
            failed = true;
        }
        b = ( a + b ) % curv->n;
        if (b == 0 ) {
            failed = true;
        }

        if (!failed) {
            b.ToBytes32BE(inout->private_key_);
            break;
        }

        // child_num <=== child_num + 1 if failed
        write_be(data + 33, ++i);

        CHMAC_SHA512(inout->chain_code_, 32)
                .Write(data, sizeof(data))
                .Finalize(I);
    }

    memcpy(inout->chain_code_, I + 32, 32);
    inout->depth_++;
    inout->child_num_ = i;
    memzero(inout->public_key_, sizeof(inout->public_key_));

    // making sure to wipe our memory
    memzero(I, sizeof(I));
    memzero(data, sizeof(data));
    return 1;
}

int hdnode_public_ckd_cp_ex(const CurvePoint &parent,
                            const uint8_t *parent_chain_code, uint32_t i,
                            CurvePoint &child, uint8_t *child_chain_code, BN &delta) {
    const Curve *curv = GetCurveParam(parent.GetCurveType());
    uint8_t data[(1 + 32) + 4] = {0};
    uint8_t I[32 + 32] = {0};

    if (i & 0x80000000) {  // private derivation
        return 0;
    }

    parent.EncodeCompressed(data);
    write_be(data + 33, i);

    while (true) {
        CHMAC_SHA512(parent_chain_code, 32)
                .Write(data, sizeof(data))
                .Finalize(I);

        BN il = BN::FromBytesBE(I, 32);
        if (il < curv->n) {
            CurvePoint point_il = curv->g * il;
            child = parent + point_il;
            if (!child.IsInfinity()) {
                if (child_chain_code) {
                    memcpy(child_chain_code, I + 32, 32);
                }

                delta = il;
                // Wipe all stack data.
                memzero(data, sizeof(data));
                memzero(I, sizeof(I));
                return 1;
            }
        }
        // child_num = child_num + 1 if failed
        write_be(data + 33, ++i);
    }
}

int hdnode_public_ckd_ex(HDNode *inout, uint32_t i, BN &delta, CurveType curve_type,
                         bool hd_node_has_private_key) {
    assert(is_valid_curve_type(static_cast<CurveType>(inout->curve_type_)));
    assert(is_valid_curve_type(static_cast<CurveType>(curve_type)));
    CurvePoint parent_pubkey;
    CurvePoint child_pubkey;
    uint8_t parent_chain_code[32];
    uint8_t child_chain_code[32];

    HDKey::GetPublicKeyEx(parent_pubkey, *inout, curve_type, hd_node_has_private_key);
    memcpy(parent_chain_code, inout->chain_code_, 32);

    if (!hdnode_public_ckd_cp_ex(parent_pubkey, parent_chain_code, i,
                                 child_pubkey, child_chain_code, delta)) {
        return 0;
    }
    memzero(inout->private_key_, 32);
    memcpy(inout->chain_code_, child_chain_code, 32);
    inout->depth_++;
    inout->child_num_ = i;
    child_pubkey.EncodeCompressed(inout->public_key_);

    // Wipe all stack data.
    memzero(parent_chain_code, 32);
    memzero(child_chain_code, 32);

    return 1;
}

// check for validity of curve point in case of public data not performed
int hdnode_deserialize_ex(const char *str, uint32_t *version,
                          bool use_private, safeheron::curve::CurveType curve_type, HDNode *node,
                          uint32_t *fingerprint) {
    assert(is_valid_curve_type(static_cast<CurveType>(curve_type)));
    uint8_t node_data[78] = {0};
    memzero(node, sizeof(HDNode));
    node->curve_type_ = static_cast<uint32_t>(curve_type);

    std::string bin = base58::DecodeFromBase58Check(str);
    if(bin.length() != sizeof(node_data)) return -1;
    memcpy(node_data, bin.c_str(), sizeof(node_data));

    uint32_t ver = read_be(node_data);
    *version = ver;

    if (use_private) {
        // invalid data
//        if (node_data[45]) {
//            return -2;
//        }
        memzero(node->public_key_, sizeof(node->public_key_));
        const Curve *curv = curve::GetCurveParam(curve_type);
        BN a;
        a = BN::FromBytesBE(node_data + 46, 32);
        if ( (a == 0) || (a >= curv->n) ){  // Invalid index
            return 0;
        }
        memcpy(node->private_key_, node_data + 46, 32);
    } else {
        memzero(node->private_key_, sizeof(node->private_key_));
        CurvePoint p;
        if(!p.DecodeCompressed(node_data + 45, curve_type)) return 0;
        memcpy(node->public_key_, node_data + 45, 33);
    }
    node->depth_ = node_data[4];
    if (fingerprint) {
        *fingerprint = read_be(node_data + 5);
    }
    node->child_num_ = read_be(node_data + 9);
    memcpy(node->chain_code_, node_data + 13, 32);
    memzero(node_data, 78);
    return 1;
}

int hdnode_deserialize_public_ex(const char *str, uint32_t *version,
                                 safeheron::curve::CurveType curve_type, HDNode *node,
                                 uint32_t *fingerprint) {
    return hdnode_deserialize_ex(str, version, false, curve_type, node, fingerprint);
}

int hdnode_deserialize_private_ex(const char *str, uint32_t *version,
                                  safeheron::curve::CurveType curve_type, HDNode *node,
                                  uint32_t *fingerprint) {
    return hdnode_deserialize_ex(str, version, true, curve_type, node, fingerprint);
}


std::string hdnode_serialize(const HDNode *node, uint32_t fingerprint,
                             uint32_t version, bool use_private) {
    assert(is_valid_curve_type(static_cast<CurveType>(node->curve_type_)));
    uint8_t node_data[78] = {0};
    write_be(node_data, version);
    node_data[4] = node->depth_;
    write_be(node_data + 5, fingerprint);
    write_be(node_data + 9, node->child_num_);
    memcpy(node_data + 13, node->chain_code_, 32);
    if (use_private) {
        node_data[45] = 0;
        memcpy(node_data + 46, node->private_key_, 32);
    } else {
        memcpy(node_data + 45, node->public_key_, 33);
    }

    std::string b58 = base58::EncodeToBase58Check(node_data, sizeof(node_data));

    memzero(node_data, sizeof(node_data));
    return b58;
}

std::string hdnode_serialize_public(const HDNode *node, uint32_t fingerprint,
                                    uint32_t version) {
    return hdnode_serialize(node, fingerprint, version, false);
}

std::string hdnode_serialize_private(const HDNode *node, uint32_t fingerprint,
                                     uint32_t version) {
    return hdnode_serialize(node, fingerprint, version, true);
}

}
}
}
