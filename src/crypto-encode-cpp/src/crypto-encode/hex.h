/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_HEX_H
#define SAFEHERON_HEX_H

#include <string>

namespace safeheron {
namespace encode {
namespace hex {

/**
 * Encode from bytes to hex string.
 * @param data
 * @return a hex string.
 */
std::string EncodeToHex(const std::string &data);

/**
 * Encode from bytes to hex string.
 * @param buf
 * @param buf_len
 * @return a hex string.
 */
std::string EncodeToHex(const unsigned char * buf, size_t buf_len);

/**
 * Decode from hex string to bytes.
 * @param hex
 * @return data in bytes.
 */
std::string DecodeFromHex(const std::string &hex);

};
};
};

#endif //SAFEHERON_HEX_H
