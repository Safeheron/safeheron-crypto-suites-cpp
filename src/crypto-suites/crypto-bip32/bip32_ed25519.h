#ifndef SAFEHERON_CRYPTO_BIP32_EDDSA_H
#define SAFEHERON_CRYPTO_BIP32_EDDSA_H

#include <string>
#include "../crypto-curve/curve.h"
#include "common.h"

namespace safeheron {
namespace bip32 {
namespace _ed25519 {

/**
 * Create hdnode(master HDKey) from seed.
 * @param[in] seed
 * @param[in] seed_len
 * @param[in] curve_type
 * @param[out] out
 * @return 1 on success, 0 on error.
 */
int hdnode_from_seed(const uint8_t *seed, int seed_len, safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *out);

/**
 * Create hdnode from private key.
 * @param[in] depth
 * @param[in] child_num
 * @param[in] chain_code
 * @param[in] private_key
 * @param[in] curve_type
 * @param[out] out
 */
int hdnode_from_xprv(uint32_t depth, uint32_t child_num,
                     const uint8_t *chain_code, const uint8_t *private_key,
                     safeheron::curve::CurveType curve_type, HDNode *out);

/**
 * Create hdnode from private key.
 * @param[in] depth
 * @param[in] child_num
 * @param[in] chain_code
 * @param[in] public_key
 * @param[in] curve_type
 * @param[out] out
 * @return 1 on success, 0 on error.
 */
int hdnode_from_xpub(uint32_t depth, uint32_t child_num,
                             const uint8_t *chain_code, const uint8_t *public_key,
                             safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *out);

/**
 * Calculate the fingerprint of HDNode.
 * @param[in] node
 * @return fingerprint
 */
uint32_t hdnode_fingerprint(const safeheron::bip32::HDNode *node);

/**
 * Fill public key if this HDNode object has private key.
 * @param[in, out] node
 */
void hdnode_fill_public_key(safeheron::bip32::HDNode *node);

/**
 * Private child key derivation.
 * @param[in,out] inout
 * @param[in] i
 * @return 1 on success
 */
int hdnode_private_ckd(safeheron::bip32::HDNode *inout, uint32_t i);

/**
 * Public child key derivation.
 * @param[in] parent
 * @param[in] parent_chain_code
 * @param[in] i
 * @param[out] child
 * @param[out] child_chain_code
 * @param[out] delta
 * @return 1 on success
 */
int hdnode_public_ckd_cp_ex(const curve::CurvePoint &parent,
                                    const uint8_t *parent_chain_code, uint32_t i,
                                    curve::CurvePoint &child, uint8_t *child_chain_code, safeheron::bignum::BN &delta);

/**
 * Public child key derivation.
 * @param[in,out] inout
 * @param[in] i
 * @param[out] delta
 * @param[in] curve_type
 * @param[in] hd_node_has_private_key denote if this hdnode has a private key.
 * @return 1 on success
 */
int hdnode_public_ckd_ex(safeheron::bip32::HDNode *inout, uint32_t i, safeheron::bignum::BN &delta, curve::CurveType curve_type,
                                 bool hd_node_has_private_key);

/**
 * Deserialization from extended key to HDNode.
 * @param[in] str extended key
 * @param[in] version
 * @param[in] use_private set true if it's a extended private key.
 * @param[in] curve_type
 * @param[out] node
 * @param[out] fingerprint
 * @return 1 on success
 */
 int hdnode_deserialize_ex(const char *str, uint32_t *version,
                                  bool use_private, safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *node,
                                  uint32_t *fingerprint);

/**
* Deserialization from public extended key to HDNode.
* @param[in] str extended public key.
* @param[in] version
* @param[in] curve_type
* @param[out] node
* @param[out] fingerprint
* @return 1 on success
*/
int hdnode_deserialize_public_ex(const char *str, uint32_t *version,
                                         safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *node,
                                         uint32_t *fingerprint);

/**
 * Deserialization from private extended key to HDNode.
 * @param[in] str extended private key.
 * @param[in] version
 * @param[in] curve_type
 * @param[out] node
 * @param[out] fingerprint
 * @return 1 on success
 */
int hdnode_deserialize_private_ex(const char *str, uint32_t *version,
                                          safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *node,
                                          uint32_t *fingerprint);

/**
 * Serialization to extended key.
 * @param[in] node
 * @param[in] fingerprint
 * @param[in] version
 * @param[in] use_private set true if it's a extended private key.
 * @return extended key
 */
std::string hdnode_serialize(const safeheron::bip32::HDNode *node, uint32_t fingerprint,
                             uint32_t version, bool use_private);

/**
 * Serialization to extended public key.
 * @param[in] node
 * @param[in] fingerprint
 * @param[in] version
 * @return extended public key
 */
std::string hdnode_serialize_public(const safeheron::bip32::HDNode *node, uint32_t fingerprint,
                                    uint32_t version);

/**
 * Serialization to extended private key.
 * @param[in] node
 * @param[in] fingerprint
 * @param[in] version
 * @return extended private key
 */
std::string hdnode_serialize_private(const safeheron::bip32::HDNode *node, uint32_t fingerprint,
                                     uint32_t version);
};
}
}


#endif //SAFEHERON_CRYPTO_BIP32_EDDSA_H
