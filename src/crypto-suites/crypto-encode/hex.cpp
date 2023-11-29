/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#include "hex.h"
#include <stdexcept>
#include <memory>
#include "hex_imp.h"

namespace safeheron {
namespace encode {
namespace hex {

std::string DecodeFromHex(const std::string &hex) {
    std::string data;
    int hex_len = hex.length();
    if(hex_len == 0) return data;
    if(hex_len % 2 != 0){
        throw std::runtime_error("Input is not valid hex-encoded data(length is even).");
    }
    unsigned int decode_out_len = hex_len / 2;
    std::unique_ptr<uint8_t[]> decode_out(new uint8_t[decode_out_len]);
    tallymarker_hex2bin(hex.c_str(), decode_out.get(), decode_out_len);
    data.assign((char *)decode_out.get(), decode_out_len);
    return data;
}

std::string EncodeToHex(const std::string &data) {
    return EncodeToHex(reinterpret_cast<const unsigned char *>(data.c_str()), data.length());
}

std::string EncodeToHex(const unsigned char * buf, size_t buf_len){
    std::string hex;
    unsigned int encode_out_len = buf_len * 2 + 1;
    std::unique_ptr<char[]> encode_out(new char [encode_out_len]);
    tallymarker_bin2hex(buf, buf_len, encode_out.get(), encode_out_len);
    hex.assign((char *)encode_out.get(), encode_out_len - 1);
    return hex;
}

};
};
};
