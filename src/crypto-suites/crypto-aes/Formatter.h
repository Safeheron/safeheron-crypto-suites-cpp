//
// Created by Sword03 on 2024/1/28.
//

#ifndef SAFEHERON_MPC_NODE_FORMATTER_H
#define SAFEHERON_MPC_NODE_FORMATTER_H

#include <cstdint>
#include <string>

class Formatter{
public:
    Formatter() = default;;

    /**
     * Parse Crypher Bytes of AES-GCM
     * Version 1
     * 01 + Len0(4 bytes) + Segment0 + Len1(4 bytes) + Segment1 + Len2(4 bytes) + Segment2
     * 01 + cypher + mac + iv
     *
     * Version 2
     * 02 + Len0(variant bytes) + Segment0 + Len1(variant bytes) + Segment1 + Len2(variant bytes) + Segment2
     * @param p_cyhper [in]
     * @param cyhper_len [in]
     * @param p_encrypted_data [out]
     * @param encrypted_data_len [out]
     * @param p_mac [out]
     * @param mac_len [out]
     * @param p_iv [out]
     * @param iv_len [out]
     * @return
     */
    bool ParseAESGCMCypher(const uint8_t *p_cyhper,
                           uint32_t cyhper_len,
                           const uint8_t * &p_encrypted_data,
                           uint32_t &encrypted_data_len,
                           const uint8_t * &p_mac,
                           uint32_t &mac_len,
                           const uint8_t * &p_iv,
                           uint32_t &iv_len);

    /**
     * Parse Crypher Bytes of AES-GCM
     * Version 1
     * 01 + Len0(4 bytes) + Segment0 + Len1(4 bytes) + Segment1 + Len2(4 bytes) + Segment2
     * 01 + cypher + mac + iv
     *
     * Version 2
     * 02 + Len0(variant bytes) + Segment0 + Len1(variant bytes) + Segment1 + Len2(variant bytes) + Segment2
     * @param cyhper [in]
     * @param p_encrypted_data [out]
     * @param encrypted_data_len [out]
     * @param p_mac [out]
     * @param mac_len [out]
     * @param p_iv [out]
     * @param iv_len [out]
     * @return
     */
    bool ParseAESGCMCypher(const std::string &cyhper,
                           const uint8_t * &p_encrypted_data,
                           uint32_t &encrypted_data_len,
                           const uint8_t * &p_mac,
                           uint32_t &mac_len,
                           const uint8_t * &p_iv,
                           uint32_t &iv_len);

    /**
     * Construct Crypher Bytes of AES-GCM
     * Version 1
     * 01 + Len0(4 bytes) + Segment0 + Len1(4 bytes) + Segment1 + Len2(4 bytes) + Segment2
     * 01 + cypher + mac + iv
     *
     * Version 2
     * 02 + Len0(variant bytes) + Segment0 + Len1(variant bytes) + Segment1 + Len2(variant bytes) + Segment2
     *
     * @param p_encrypted_data [in]
     * @param encrypted_data_len  [in]
     * @param p_mac  [in]
     * @param mac_len  [in]
     * @param p_iv  [in]
     * @param iv_len  [in]
     * @param cyhper  [out]
     * @return
     */
    bool ConstructAESGCMCypher(const uint8_t * p_encrypted_data,
                               uint32_t encrypted_data_len,
                               const uint8_t * p_mac,
                               uint32_t mac_len,
                               const uint8_t * p_iv,
                               uint32_t iv_len,
                               std::string &cypher);
};


#endif //SAFEHERON_MPC_NODE_FORMATTER_H
