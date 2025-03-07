//
// Created by Sword03 on 2024/1/28.
//

#include "Formatter.h"
#include "../common/MemoryWalker.h"
#include "../common/MemoryWriter.h"

/**
 * Parse Crypher Bytes of AES-GCM
 * Version 1
 * 01 + Len0(4 bytes) + Segment0 + Len1(4 bytes) + Segment1 + Len2(4 bytes) + Segment2
 * 01 + cypher + mac + iv
 *
 * Version 2
 * 02 + Len0(variant bytes) + Segment0 + Len1(variant bytes) + Segment1 + Len2(variant bytes) + Segment2
 * @param p_cyhper
 * @param cyhper_len
 * @param p_encrypted_data
 * @param encrypted_data_len
 * @param p_mac
 * @param mac_len
 * @param p_iv
 * @param iv_len
 * @return
 */
bool Formatter::ParseAESGCMCypher(const uint8_t *p_cyhper,
                       uint32_t cyhper_len,
                       const uint8_t * &p_encrypted_data,
                       uint32_t &encrypted_data_len,
                       const uint8_t * &p_mac,
                       uint32_t &mac_len,
                       const uint8_t * &p_iv,
                       uint32_t &iv_len){
    bool ok = false;
    if(cyhper_len < (1 + 3 * 4) ) return false;

    safeheron::memory::MemoryWalker walker(p_cyhper, cyhper_len);

    // type = 0x01
    uint8_t type;
    ok = walker.move_byte(type) && (type == 0x01);
    if(!ok) return false;

    // encrypted_data
    // - encrypted_data_len
    ok = walker.move_uint32(encrypted_data_len);
    if(!ok) return false;
    // - p_encrypted_data
    ok = walker.move_buf(p_encrypted_data, encrypted_data_len);
    if(!ok) return false;

    // mac
    // - mac_len
    ok = walker.move_uint32(mac_len);
    if(!ok) return false;
    // - p_mac
    ok = walker.move_buf(p_mac, mac_len);
    if(!ok) return false;

    // iv
    // - iv_len
    ok = walker.move_uint32(iv_len);
    if(!ok) return false;
    // - p_iv
    ok = walker.move_buf(p_iv, iv_len);
    if(!ok) return false;

    return true;
}

bool Formatter::ParseAESGCMCypher(const std::string &cyhper,
                                  const uint8_t * &p_encrypted_data,
                                  uint32_t &encrypted_data_len,
                                  const uint8_t * &p_mac,
                                  uint32_t &mac_len,
                                  const uint8_t * &p_iv,
                                  uint32_t &iv_len){
    return ParseAESGCMCypher((const uint8_t *)(cyhper.c_str()), cyhper.length(),
                          p_encrypted_data, encrypted_data_len,
                          p_mac, mac_len,
                          p_iv, iv_len);
}

bool Formatter::ConstructAESGCMCypher(const uint8_t * p_encrypted_data,
                          const uint32_t encrypted_data_len,
                          const uint8_t * p_mac,
                          const uint32_t mac_len,
                          const uint8_t * p_iv,
                          const uint32_t iv_len,
                          std::string &cypher){
    bool ok = false;
    uint32_t output_len = 1 + 3 * 4 + encrypted_data_len + mac_len + iv_len;
    std::unique_ptr<uint8_t[]> p_output(new uint8_t[output_len]);

    safeheron::memory::MemoryWriter mem_writer(p_output.get(), output_len);

    // 0x01
    ok = mem_writer.write_byte(0x01);
    if(!ok) return false;

    // encrypted_data
    ok = mem_writer.write_uint32(encrypted_data_len);
    if(!ok) return false;
    ok = mem_writer.write_buf(p_encrypted_data, encrypted_data_len);
    if(!ok) return false;

    // mac
    ok = mem_writer.write_uint32(mac_len);
    if(!ok) return false;
    ok = mem_writer.write_buf(p_mac, mac_len);
    if(!ok) return false;

    // iv
    ok = mem_writer.write_uint32(iv_len);
    if(!ok) return false;
    ok = mem_writer.write_buf(p_iv, iv_len);
    if(!ok) return false;

    if(mem_writer.left() != 0) return false;

    cypher.assign((char *)p_output.get(), output_len);

    return true;
}
