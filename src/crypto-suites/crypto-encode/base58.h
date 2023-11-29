/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_BASE58_H
#define SAFEHERON_BASE58_H

#include <string>
#include <vector>

namespace safeheron {
namespace encode {
namespace base58 {

/**
 * Why base-58 instead of standard base-64 encoding?
 * - Don't want 0OIl characters that look the same in some fonts and
 *      could be used to create visually identical looking data.
 * - A string with non-alphanumeric characters is not as easily accepted as input.
 * - E-mail usually won't line-break if there's no punctuation to break at.
 * - Double-clicking selects the whole string as one word if it's all alphanumeric.
 */

/**
 * Encode from bytes to base58.
 * @param data in bytes.
 * @return a string in base58.
 */
std::string EncodeToBase58(const std::string &data);

/**
 * Encode from bytes to base58.
 * @param buf
 * @param buf_len
 * @return a string in base58.
 */
std::string EncodeToBase58(unsigned char const *buf, size_t buf_len);

/**
 * Decode from base58 to bytes
 * @param base58
 * @return data in bytes
 */
std::string DecodeFromBase58(const std::string &base58);


/**
 * Encode from bytes to base58check.
 * @param data
 * @return a string in base58check.
 */
std::string EncodeToBase58Check(const std::string &data);

/**
 * Encode from bytes to base58check.
 * @param buf
 * @param buf_len
 * @return a string in base58check.
 */
std::string EncodeToBase58Check(unsigned char const *buf, size_t buf_len);

/**
 * Decode from base58check string to bytes
 * @param base58
 * @return data in bytes
 */
std::string DecodeFromBase58Check(const std::string &base58);

}
}
}
#endif // SAFEHERON_BASE58_H
