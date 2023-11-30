#include "crypto-suites/exception/located_exception.h"
#include "crypto-suites/crypto-bip32/bip32.h"
#include "crypto-suites/crypto-bip32/hd_path.h"
#include "crypto-suites/crypto-bip32/bip32_ed25519.h"
#include "crypto-suites/crypto-bip32/bip32_ecdsa.h"
#include "crypto-suites/crypto-bip32/common.h"
#include "crypto-suites/crypto-bip32/memzero.h"


using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::bip32::HDPath;
using safeheron::bip32::HDKey;
using safeheron::bip32::Bip32Version;

namespace safeheron{
namespace bip32 {


const char *CURVE_NAME_SECP256k1 = "secp256k1";
const char *CURVE_NAME_P256 = "nist256p1";
const char *CURVE_NAME_ED25519 = "ed25519";
const char * get_curve_name(CurveType c_type){
    switch (c_type) {
        case CurveType::SECP256K1:
            return CURVE_NAME_SECP256k1;
        case CurveType::P256:
            return CURVE_NAME_P256;
        case CurveType::ED25519:
            return CURVE_NAME_ED25519;
        default:
            return nullptr;
    }
}

Bip32Version get_coin_version(CurveType c_type, bool is_private_key){
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
            if(is_private_key) {
                return Bip32Version::BITCOIN_VERSION_PRIVATE;
            }else{
                return Bip32Version::BITCOIN_VERSION_PUBLIC;
            }
        case CurveType::ED25519:
            if(is_private_key) {
                return Bip32Version::EDDSA_VERSIONS_PRIVATE;
            }else{
                return Bip32Version::EDDSA_VERSIONS_PUBLIC;
            }
        default:
            return Bip32Version::INVALID_VERSION;
    }
}

HDKey::HDKey() {
    curve_type_ = CurveType::INVALID_CURVE;
    fingerprint_ = 0;
    memset(&hd_node_, 0, sizeof(HDNode));
}


HDKey::HDKey(const HDKey &hd_key) {
    fingerprint_ = hd_key.fingerprint_;
    curve_type_ = hd_key.curve_type_;
    hd_node_ = hd_key.hd_node_;
}

HDKey &HDKey::operator=(const HDKey &hd_key) {
    if(this == &hd_key) return *this;
    fingerprint_ = hd_key.fingerprint_;
    curve_type_ = hd_key.curve_type_;
    hd_node_ = hd_key.hd_node_;
    return *this;
}

HDKey::~HDKey() {
    fingerprint_ = 0;
    curve_type_ = CurveType::INVALID_CURVE;
    crypto_bip32_memzero(&hd_node_, sizeof(HDNode));
}

HDKey HDKey::CreateHDKey(CurveType c_type, const BN &private_key, const uint8_t *chain_code,
                         uint32_t depth, uint32_t child_num, uint32_t fingerprint) {
    HDKey hd_key;
    hd_key.curve_type_ = c_type;
    hd_key.fingerprint_ = fingerprint;
    memset(&hd_key.hd_node_, 0, sizeof(HDNode));

    int ret;
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            uint8_t priv[32];
            private_key.ToBytes32BE(priv);
            ret = _ecdsa::hdnode_from_xprv(depth, child_num, chain_code, priv, c_type, &hd_key.hd_node_);
            crypto_bip32_memzero(priv, 32);
            if (ret != 1) throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "_ecdsa::hdnode_from_xprv failed.");
            break;
        }
        case CurveType::ED25519:
        {
            uint8_t priv[32];
            private_key.ToBytes32LE(priv);
            ret = _ed25519::hdnode_from_xprv(depth, child_num, chain_code, priv, CurveType::ED25519, &hd_key.hd_node_);
            crypto_bip32_memzero(priv, 32);
            if (ret != 1) throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "_ed25519::hdnode_from_xprv failed.");
            break;
        }
        default:
            throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "Invalid curve type.");
    }

    return hd_key;
}

bool HDKey::CreateHDKey(HDKey &hd_key, safeheron::curve::CurveType c_type, const safeheron::bignum::BN & private_key, const uint8_t *chain_code,
                        uint32_t depth, uint32_t child_num, uint32_t fingerprint) {
    hd_key.curve_type_ = c_type;
    hd_key.fingerprint_ = fingerprint;
    memset(&hd_key.hd_node_, 0, sizeof(HDNode));

    int ret;
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            uint8_t priv[32];
            private_key.ToBytes32BE(priv);
            ret = _ecdsa::hdnode_from_xprv(depth, child_num, chain_code, priv, c_type, &hd_key.hd_node_);
            crypto_bip32_memzero(priv, 32);
            if (ret != 1) return false;
            break;
        }
        case CurveType::ED25519:
        {
            uint8_t priv[32];
            private_key.ToBytes32LE(priv);
            ret = _ed25519::hdnode_from_xprv(depth, child_num, chain_code, priv, CurveType::ED25519, &hd_key.hd_node_);
            crypto_bip32_memzero(priv, 32);
            if (ret != 1) return false;
            break;
        }
        default:
            return false;
    }

    return true;
}

HDKey HDKey::CreateHDKey(safeheron::curve::CurveType c_type, const safeheron::curve::CurvePoint & public_key, const uint8_t *chain_code,
                         uint32_t depth, uint32_t child_num, uint32_t fingerprint) {
    HDKey hd_key;
    hd_key.curve_type_ = c_type;
    hd_key.fingerprint_ = fingerprint;
    memset(&hd_key.hd_node_, 0, sizeof(HDNode));

    int ret;
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            uint8_t pub33[33];
            public_key.EncodeCompressed(pub33);
            ret = _ecdsa::hdnode_from_xpub(depth, child_num, chain_code, pub33, c_type, &hd_key.hd_node_);
            if (ret != 1) throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "_ecdsa::hdnode_from_xpub failed.");
            break;
        }
        case CurveType::ED25519:
        {
            // pub33 = 0x00 || pub32
            uint8_t pub33[33];
            pub33[0] = 0x0;
            public_key.EncodeEdwardsPoint((uint8_t *)(pub33 + 1));
            ret = _ed25519::hdnode_from_xpub(depth, child_num, chain_code, pub33, CurveType::ED25519, &hd_key.hd_node_);
            if (ret != 1) throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "_eddsa::hdnode_from_xpub failed.");
            break;
        }
        default:
            throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "Invalid curve type.");
    }

    return hd_key;
}

bool HDKey::CreateHDKey(HDKey &hd_key, safeheron::curve::CurveType c_type, const safeheron::curve::CurvePoint & public_key, const uint8_t *chain_code,
                        uint32_t depth, uint32_t child_num, uint32_t fingerprint) {
    hd_key.curve_type_ = c_type;
    hd_key.fingerprint_ = fingerprint;
    memset(&hd_key.hd_node_, 0, sizeof(HDNode));

    int ret;
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            uint8_t pub33[33];
            public_key.EncodeCompressed(pub33);
            ret = _ecdsa::hdnode_from_xpub(depth, child_num, chain_code, pub33, c_type, &hd_key.hd_node_);
            if (ret != 1) return false;
            break;
        }
        case CurveType::ED25519:
        {
            // pub33 = 0x00 || pub32
            uint8_t pub33[33];
            pub33[0] = 0x0;
            public_key.EncodeEdwardsPoint((uint8_t *)(pub33 + 1));
            ret = _ed25519::hdnode_from_xpub(depth, child_num, chain_code, pub33, CurveType::ED25519, &hd_key.hd_node_);
            if (ret != 1) return false;
            break;
        }
        default:
            return false;
    }

    return true;
}

bool HDKey::HasPrivateKey() const {
    uint8_t ret = 0;
    for(int i = 0; i < 32; ++i){
        ret |= hd_node_.private_key_[i];
    }
    return ret != 0;
}

void HDKey::GetPrivateKey(BN &priv) const {
    switch (curve_type_) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            priv = BN::FromBytesBE(hd_node_.private_key_, 32);
            break;
        }
        case CurveType::ED25519:
        {
            priv = BN::FromBytesLE(hd_node_.private_key_, 32);
            break;
        }
        default:
            break;
    }
}

void HDKey::GetPrivateKey(uint8_t *buf32) const {
    memcpy(buf32, hd_node_.private_key_, 32);
}


void HDKey::GetPublicKey(CurvePoint &point) const {
    HDKey::GetPublicKeyEx(point, hd_node_, curve_type_, HasPrivateKey());
}

void HDKey::GetChainCode(uint8_t *buf32) const {
    memcpy(buf32, hd_node_.chain_code_, 32);
}

void HDKey::GetPublicKeyEx(CurvePoint &point, const HDNode &hd_node, CurveType curve_type, bool hd_node_has_private_key) {
    switch (curve_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            if (hd_node_has_private_key){
                const Curve * curv = GetCurveParam(curve_type);
                BN priv = BN::FromBytesBE(hd_node.private_key_, 32);
                point = curv->g * priv;
            } else{
                point.DecodeCompressed(hd_node.public_key_, curve_type);
            }
            break;
        }
        case CurveType::ED25519:
        {
            if (hd_node_has_private_key){
                const Curve * curv = GetCurveParam(curve_type);
                BN priv = BN::FromBytesLE(hd_node.private_key_, 32);
                point = curv->g * priv;
            } else{
                uint8_t * pub32 = (uint8_t *)(hd_node.public_key_ + 1);
                point.DecodeEdwardsPoint(pub32, curve_type);
            }
            break;
        }
        default:
            break;
    }
}

HDKey HDKey::PrivateCKD(uint32_t i) const{
    switch (curve_type_) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            HDNode hd_node = hd_node_;
            uint32_t fingerprint = safeheron::bip32::_ecdsa::hdnode_fingerprint(&hd_node);
            //always returns 1
            _ecdsa::hdnode_private_ckd(&hd_node, i);

            HDKey child_key(*this);
            child_key.hd_node_ = hd_node;
            child_key.fingerprint_ = fingerprint;
            crypto_bip32_memzero(&hd_node, sizeof(HDNode));
            return child_key;
        }
        case CurveType::ED25519:
        {
            HDNode hd_node = hd_node_;
            uint32_t fingerprint = safeheron::bip32::_ed25519::hdnode_fingerprint(&hd_node);
            //always returns 1
            _ed25519::hdnode_private_ckd(&hd_node, i);

            HDKey child_key(*this);
            child_key.hd_node_ = hd_node;
            child_key.fingerprint_ = fingerprint;
            crypto_bip32_memzero(&hd_node, sizeof(HDNode));
            return child_key;
        }
        default:
            throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "Invalid curve type.");
    }
}

HDKey HDKey::PublicCKD(uint32_t i, safeheron::bignum::BN &delta) const{
    int ret;
    switch (curve_type_) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            const curve::Curve *curv = curve::GetCurveParam(curve_type_);
            BN total_delta(0);
            HDNode hd_node = hd_node_;
            uint32_t fingerprint = 0;

            BN d(0);
            fingerprint = safeheron::bip32::_ecdsa::hdnode_fingerprint(&hd_node);
            ret = _ecdsa::hdnode_public_ckd_ex(&hd_node, i, d, curve_type_, HasPrivateKey());
            if (ret != 1) throw safeheron::exception::LocatedException(__FILE__, __LINE__, __FUNCTION__, 1, " _ecdsa::hdnode_public_ckd_ex failed.");
            total_delta = (total_delta + d) % curv->n;

            delta = total_delta;

            HDKey child_key(*this);
            child_key.hd_node_ = hd_node;
            child_key.fingerprint_ = fingerprint;
            crypto_bip32_memzero(&hd_node, sizeof(HDNode));
            return child_key;
        }
        case CurveType::ED25519:
        {
            const curve::Curve *curv = curve::GetCurveParam(CurveType::ED25519);
            BN total_delta(0);
            HDNode hd_node = hd_node_;
            uint32_t fingerprint = 0;

            BN d(0);
            fingerprint = safeheron::bip32::_ed25519::hdnode_fingerprint(&hd_node);
            ret = _ed25519::hdnode_public_ckd_ex(&hd_node, i, d, curve_type_, HasPrivateKey());
            if (ret != 1) throw safeheron::exception::LocatedException(__FILE__, __LINE__, __FUNCTION__, 1, " _ed25519::hdnode_public_ckd_ex failed.");
            total_delta = (total_delta + d) % curv->n;

            delta = total_delta;

            HDKey child_key(*this);
            child_key.hd_node_ = hd_node;
            child_key.fingerprint_ = fingerprint;
            crypto_bip32_memzero(&hd_node, sizeof(HDNode));
            return child_key;
        }
        default:
            throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "Invalid curve type.");
    }
}

bool HDKey::PublicCKD(HDKey &child_key, uint32_t i, safeheron::bignum::BN &delta) const {
    int ret;
    switch (curve_type_) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            const curve::Curve *curv = curve::GetCurveParam(curve_type_);
            BN total_delta(0);
            HDNode hd_node = hd_node_;
            uint32_t fingerprint = 0;

            BN d(0);
            fingerprint = safeheron::bip32::_ecdsa::hdnode_fingerprint(&hd_node);
            ret = _ecdsa::hdnode_public_ckd_ex(&hd_node, i, d, curve_type_, HasPrivateKey());
            if (ret != 1) return false;
            total_delta = (total_delta + d) % curv->n;

            delta = total_delta;

            child_key = *this;
            child_key.hd_node_ = hd_node;
            child_key.fingerprint_ = fingerprint;
            crypto_bip32_memzero(&hd_node, sizeof(HDNode));
            return true;
        }
        case CurveType::ED25519:
        {
            const curve::Curve *curv = curve::GetCurveParam(CurveType::ED25519);
            BN total_delta(0);
            HDNode hd_node = hd_node_;
            uint32_t fingerprint = 0;

            BN d(0);
            fingerprint = safeheron::bip32::_ed25519::hdnode_fingerprint(&hd_node);
            ret = _ed25519::hdnode_public_ckd_ex(&hd_node, i, d, curve_type_, HasPrivateKey());
            if (ret != 1) return false;
            total_delta = (total_delta + d) % curv->n;

            delta = total_delta;

            child_key = *this;
            child_key.hd_node_ = hd_node;
            child_key.fingerprint_ = fingerprint;
            crypto_bip32_memzero(&hd_node, sizeof(HDNode));
            return true;
        }
        default:
            return false;
    }
}


HDKey HDKey::PublicCKD(uint32_t i) const{
    BN delta;
    return PublicCKD(i, delta);
}

bool HDKey::PublicCKD(HDKey &child_key, uint32_t i) const {
    BN delta;
    return PublicCKD(child_key, i, delta);
}

HDKey HDKey::PrivateCKDPath(const char *path) const {
    std::vector<uint32_t> hd_path;
    if (!HDPath::ParseHDPath(path, hd_path)) {
        throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "Invalid path.");
    }
    HDKey child_key(*this);
    for(size_t i = 0; i < hd_path.size(); ++i){
        child_key = child_key.PrivateCKD(hd_path[i]);
    }
    return child_key;
}

bool HDKey::PrivateCKDPath(HDKey &child_key, const char * path) const {
    std::vector<uint32_t> hd_path;
    if (!HDPath::ParseHDPath(path, hd_path)) return false;
    child_key = *this;
    for(size_t i = 0; i < hd_path.size(); ++i){
        child_key = child_key.PrivateCKD(hd_path[i]);
    }
    return true;
}

HDKey HDKey::PrivateCKDPath(const std::string &path) const {
    return PrivateCKDPath(path.c_str());
}

bool HDKey::PrivateCKDPath(HDKey &child_key, const std::string &path) const {
    return PrivateCKDPath(child_key, path.c_str());
}

HDKey HDKey::PublicCKDPath(const char *path, BN &delta) const {
    std::vector<uint32_t> hd_path;
    const Curve * curv = GetCurveParam(curve_type_);
    if (!HDPath::ParseHDPath(path, hd_path)) {
        throw safeheron::exception::LocatedException(__FILE__,  __LINE__, __FUNCTION__, 1, "Invalid path.");
    }
    HDKey child_key(*this);
    delta = BN(0);
    for(size_t i = 0; i < hd_path.size(); ++i){
        // Normal(No harden) derive
        BN t_delta;
        child_key = child_key.PublicCKD(hd_path[i], t_delta);
        delta = (delta + t_delta) % curv->n;
    }
    return child_key;
}

bool HDKey::PublicCKDPath(HDKey &child_key, const char *path, safeheron::bignum::BN &delta) const {
    std::vector<uint32_t> hd_path;
    const Curve * curv = GetCurveParam(curve_type_);
    if (!HDPath::ParseHDPath(path, hd_path)) return false;
    child_key = *this;
    //HDKey child_key(*this);
    delta = BN(0);
    int ret;
    for(size_t i = 0; i < hd_path.size(); ++i){
        // Normal(No harden) derive
        BN t_delta;
        //hd_key = hd_key.PublicCKD(hd_path[i], t_delta);
        ret = child_key.PublicCKD(child_key, hd_path[i], t_delta);
        if (ret != 1) return false;
        delta = (delta + t_delta) % curv->n;
    }
    return true;
}

HDKey HDKey::PublicCKDPath(const std::string &path, BN &delta) const {
    return PublicCKDPath(path.c_str(), delta);
}

bool HDKey::PublicCKDPath(HDKey &child_key, const std::string &path, safeheron::bignum::BN &delta) const {
    return PublicCKDPath(child_key, path.c_str(), delta);
}

HDKey HDKey::PublicCKDPath(const char *path) const {
    BN delta;
    return PublicCKDPath(path, delta);
}

bool HDKey::PublicCKDPath(HDKey &child_key, const char *path) const {
    BN delta;
    return PublicCKDPath(child_key, path, delta);
}

HDKey HDKey::PublicCKDPath(const std::string &path) const {
    BN delta;
    return PublicCKDPath(path, delta);
}

bool HDKey::PublicCKDPath(HDKey &child_key, const std::string &path) const {
    BN delta;
    return PublicCKDPath(child_key, path, delta);
}


bool HDKey::FromExtendedPublicKey(const char *xpub, CurveType c_type) {
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            uint32_t fingerprint = 0;
            uint32_t version = 0;
            int ret = _ecdsa::hdnode_deserialize_public_ex(xpub, &version, c_type, &hd_node_, &fingerprint);
            curve_type_ = c_type;
            fingerprint_ = fingerprint;
            return ret == 1 && (version == static_cast<uint32_t>(Bip32Version::BITCOIN_VERSION_PUBLIC));
        }
        case CurveType::ED25519:
        {
            uint32_t fingerprint = 0;
            uint32_t version = 0;
            int ret = _ed25519::hdnode_deserialize_public_ex(xpub, &version, CurveType::ED25519, &hd_node_, &fingerprint);
            curve_type_ = c_type;
            fingerprint_ = fingerprint;
            return ret == 1 && (version == static_cast<uint32_t>(Bip32Version::EDDSA_VERSIONS_PUBLIC));
        }
        default:
            return false;
    }
}

bool HDKey::FromExtendedPublicKey(const std::string &xpub, CurveType c_type) {
    return FromExtendedPublicKey(xpub.c_str(), c_type);
}

bool HDKey::FromExtendedPrivateKey(const char *xprv, CurveType c_type) {
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            uint32_t fingerprint = 0;
            uint32_t version = 0;
            int ret = _ecdsa::hdnode_deserialize_private_ex(xprv, &version, c_type, &hd_node_, &fingerprint);
            curve_type_ = c_type;
            fingerprint_ = fingerprint;
            return ret == 1 && (version == static_cast<uint32_t>(Bip32Version::BITCOIN_VERSION_PRIVATE));
        }
        case CurveType::ED25519:
        {
            uint32_t fingerprint = 0;
            uint32_t version = 0;
            int ret = _ed25519::hdnode_deserialize_private_ex(xprv, &version, CurveType::ED25519, &hd_node_, &fingerprint);
            curve_type_ = c_type;
            fingerprint_ = fingerprint;
            return ret == 1 && (version == static_cast<uint32_t>(Bip32Version::EDDSA_VERSIONS_PRIVATE));
        }
        default:
            return false;
    }
}

bool HDKey::FromExtendedPrivateKey(const std::string &xprv, CurveType c_type) {
    return FromExtendedPrivateKey(xprv.c_str(), c_type);
}

bool HDKey::ToExtendedPrivateKey(std::string &xprv) const {
    switch (curve_type_) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            xprv = _ecdsa::hdnode_serialize_private(&hd_node_, fingerprint_, static_cast<uint32_t>(get_coin_version(curve_type_, true)));
            return true;
        }
        case CurveType::ED25519:
        {
            xprv = _ed25519::hdnode_serialize_private(&hd_node_, fingerprint_, static_cast<uint32_t>(get_coin_version(curve_type_, true)));
            return true;
        }
        default:
            return false;
    }
}

bool HDKey::ToExtendedPublicKey(std::string &xpub) const {
    switch (curve_type_) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            HDNode t_node = hd_node_;
            _ecdsa::hdnode_fill_public_key(&t_node);
            xpub = _ecdsa::hdnode_serialize_public(&t_node, fingerprint_, static_cast<uint32_t>(get_coin_version(curve_type_, false)));
            crypto_bip32_memzero(&t_node, sizeof(t_node));
            return true;
        }
        case CurveType::ED25519:
        {
            HDNode t_node = hd_node_;
            _ed25519::hdnode_fill_public_key(&t_node);
            xpub = _ed25519::hdnode_serialize_public(&t_node, fingerprint_, static_cast<uint32_t>(get_coin_version(curve_type_, false)));
            crypto_bip32_memzero(&t_node, sizeof(t_node));
            return true;
        }
        default:
            return false;
    }
}

bool HDKey::FromSeed(CurveType curve_type, const uint8_t *seed, int seed_len) {
    curve_type_ = curve_type;
    fingerprint_ = 0;
    switch (curve_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
        {
            return _ecdsa::hdnode_from_seed(seed, seed_len, curve_type, &hd_node_) == 1;
        }
        case CurveType::ED25519:
        {
            return _ed25519::hdnode_from_seed(seed, seed_len, curve::CurveType::ED25519, &hd_node_) == 1;
        }
        default:
            return false;
    }
}

}
}
