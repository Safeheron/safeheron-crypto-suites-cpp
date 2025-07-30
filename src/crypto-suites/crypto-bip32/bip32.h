#ifndef SAFEHERON_CRYPTO_BIP32_H
#define SAFEHERON_CRYPTO_BIP32_H

#include <cstdint>
#include <string>
#include <vector>
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bip32/common.h"

namespace safeheron {
namespace bip32{


/**
 * Hierarchical Deterministic Key
 */
class HDKey {
    safeheron::curve::CurveType curve_type_;
    HDNode hd_node_;
    uint32_t fingerprint_;

public:
    /**
     * Constructor
     */
    HDKey();

    /**
     * Copy constructor
     * @param[in] hd_key
     */
    HDKey(const HDKey &hd_key);

    /**
     * Copy assignment operator
     * @param[in] hd_key
     * @return A HDKey object
     */
    HDKey &operator=(const HDKey &hd_key); // copy assignment

    /**
     * Destructor
     */
    ~HDKey();

    /**
     * Creat a HDKey object.
     * @param[in] c_type type of elliptic curve.
     * @param[in] private_key
     * @param[in] chain_code
     * @param[in] depth
     * @param[in] child_num
     * @param[in] fingerprint
     * @return a HDKey object.
     */
    static HDKey CreateHDKey(safeheron::curve::CurveType c_type, const safeheron::bignum::BN & private_key, const uint8_t *chain_code, uint32_t depth=0, uint32_t child_num=0, uint32_t fingerprint=0);

     /**
      * Creat a HDKey object.
      * @param hd_key the output HDKey object
      * @param c_type type of elliptic curve.
      * @param private_key
      * @param chain_code
      * @param depth
      * @param child_num
      * @param fingerprint
      * @return
      */
    static bool CreateHDKey(HDKey &hd_key, safeheron::curve::CurveType c_type, const safeheron::bignum::BN & private_key, const uint8_t *chain_code, uint32_t depth=0, uint32_t child_num=0, uint32_t fingerprint=0);


    /**
     * Creat a HDKey object.
     * @param[in] c_type
     * @param[in] public_key
     * @param[in] chain_code
     * @param[in] depth
     * @param[in] child_num
     * @param[in] fingerprint
     * @return a HDKey object.
     */
    static HDKey CreateHDKey(safeheron::curve::CurveType c_type, const safeheron::curve::CurvePoint & public_key, const uint8_t *chain_code, uint32_t depth=0, uint32_t child_num=0, uint32_t fingerprint=0);

    /**
     * Creat a HDKey object.
     * @param hd_key the output HDKey object
     * @param c_type
     * @param public_key
     * @param chain_code
     * @param depth
     * @param child_num
     * @param fingerprint
     * @return
     */
    static bool CreateHDKey(HDKey &hd_key, safeheron::curve::CurveType c_type, const safeheron::curve::CurvePoint & public_key, const uint8_t *chain_code, uint32_t depth=0, uint32_t child_num=0, uint32_t fingerprint=0);


    /**
     * Check if this HDKey has a private key.
     * @return
     */
    bool HasPrivateKey() const;

    /**
     * Get private key.
     * @param[out] priv
     */
    void GetPrivateKey(safeheron::bignum::BN &priv) const;

    /**
     * Get private key.
     * @param[out] buf32
     */
    void GetPrivateKey(uint8_t *buf32) const;

    /**
     * Get public key.
     * @param[out] point
     */
    void GetPublicKey(safeheron::curve::CurvePoint &point) const;

    /**
     * Get public key.
     * @param[out] point
     * @param[in] hd_node
     * @param[in] curve_type
     * @param[in] hd_node_is_private
     */
    static void GetPublicKeyEx(safeheron::curve::CurvePoint &point, const HDNode &hd_node, safeheron::curve::CurveType curve_type, bool hd_node_is_private);

    /**
     * Get chain code
     * @param[out] buf32
     */
    void GetChainCode(uint8_t *buf32) const;

    /**
     * Private child key derivation.
     * @param[in] i
     * @return a HDKey object.
     */
    HDKey PrivateCKD(uint32_t i) const;

    /**
     * Public child key derivation.
     * @param[in] i
     * @return a HDKey object.
     */
    HDKey PublicCKD(uint32_t i) const;

    /**
     *  Public child key derivation.
     * @param child_key the derived HDKey object
     * @param i
     * @return
     */
    bool PublicCKD(HDKey &child_key, uint32_t i) const;

    /**
     * Public child key derivation.
     * @param[in] i
     * @param[out] delta delta = (child - parent) mod order
     * @return a HDKey object.
     */
    HDKey PublicCKD(uint32_t i, safeheron::bignum::BN &delta) const;

     /**
      * Public child key derivation.
      * @param child_key the derived HDKey object
      * @param i
      * @param delta delta = (child - parent) mod order
      * @return
      */
    bool PublicCKD(HDKey &child_key, uint32_t i, safeheron::bignum::BN &delta) const;

    /**
     * Private child key derivation according to specified path.
     * @param[in] path
     * @return a HDKey object.
     */
    HDKey PrivateCKDPath(const char * path) const;

    /**
     * Private child key derivation according to specified path.
     * @param child_key the derived HDKey object
     * @param path
     * @return
     */
    bool PrivateCKDPath(HDKey &child_key, const char * path) const;

    /**
     * Private child key derivation according to specified path.
     * @param[in] path
     * @return a HDKey object.
     */
    HDKey PrivateCKDPath(const std::string &path) const;

     /**
      * Private child key derivation according to specified path.
      * @param child_key the derived HDKey object
      * @param path
      * @return
      */
    bool PrivateCKDPath(HDKey &child_key, const std::string &path) const;

    /**
     * Public child key derivation according to specified path.
     * @param[in] path
     * @param[out] delta delta = (child - parent) mod order
     * @return a HDKey object.
     */
    HDKey PublicCKDPath(const char *path, safeheron::bignum::BN &delta) const;

     /**
      * Public child key derivation according to specified path.
      * @param child_key the derived HDKey object
      * @param path
      * @param delta delta = (child - parent) mod order
      * @return
      */
    bool PublicCKDPath(HDKey &child_key, const char *path, safeheron::bignum::BN &delta) const;

    /**
     * Public child key derivation according to specified path.
     * @param[in] path
     * @param[out] delta delta = (child - parent) mod order
     * @return
     */
    HDKey PublicCKDPath(const std::string &path, safeheron::bignum::BN &delta) const;

     /**
      * Public child key derivation according to specified path.
      * @param child_key the derived HDKey object
      * @param path
      * @param delta delta = (child - parent) mod order
      * @return
      */
    bool PublicCKDPath(HDKey &child_key, const std::string &path, safeheron::bignum::BN &delta) const;


    /**
     * Public child key derivation according to specified path.
     * @param[in] path
     * @return
     */
    HDKey PublicCKDPath(const char *path) const;

     /**
      * Public child key derivation according to specified path.
      * @param child_key the derived HDKey object
      * @param path
      * @return
      */
    bool PublicCKDPath(HDKey &child_key, const char *path) const;


    /**
     * Public child key derivation according to specified path.
     * @param[in] path
     * @return
     */
    HDKey PublicCKDPath(const std::string &path) const;

     /**
      * Public child key derivation according to specified path.
      * @param child_key the derived HDKey object
      * @param path
      * @return
      */
    bool PublicCKDPath(HDKey &child_key, const std::string &path) const;


    /**
     * Deserialize the extended public key and set this HDKey.
     * @param[in] xpub
     * @param[in] c_type
     * @return true on success, false on error
     */
    bool FromExtendedPublicKey(const char * xpub, safeheron::curve::CurveType c_type);

    /**
     * Deserialize the extended public key and set this HDKey.
     * @param[in] xpub
     * @param[in] c_type
     * @return true on success, false on error
     */
    bool FromExtendedPublicKey(const std::string &xpub, safeheron::curve::CurveType c_type);

    /**
     * Deserialize the extended private key and set this HDKey.
     * @param[in] xprv
     * @param[in] c_type
     * @return true on success, false on error
     */
    bool FromExtendedPrivateKey(const char * xprv, safeheron::curve::CurveType c_type);

    /**
     * Deserialize the extended private key and set this HDKey.
     * @param[in] xprv
     * @param[in] c_type
     * @return true on success, false on error
     */
    bool FromExtendedPrivateKey(const std::string &xprv, safeheron::curve::CurveType c_type);

    /**
     * Serialize this HDKey to extended public key.
     * @param[out] xpub
     * @return true on success, false on error
     */
    bool ToExtendedPublicKey(std::string &xpub) const;

    /**
     * Serialize this HDKey to extended private key.
     * @param[out] xpub
     * @return true on success, false on error
     */
    bool ToExtendedPrivateKey(std::string &xprv) const;

    /**
     * Set this HDKey(Master HDKey) from seed.
     * @param curve_type
     * @param seed
     * @param seed_len
     * @return true on success, false on error
     */
    bool FromSeed(safeheron::curve::CurveType curve_type, const uint8_t *seed, int seed_len);
};

};
};


#endif //SAFEHERON_CRYPTO_BIP32_H
