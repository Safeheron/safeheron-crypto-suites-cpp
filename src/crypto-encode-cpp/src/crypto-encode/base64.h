/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_BASE64_H
#define SAFEHERON_BASE64_H

#include <string>

namespace safeheron {
namespace encode {
namespace base64 {

/**
 * Encode from bytes to base64
 * @param data
 * @param url use urlbase64 if 'url' is set true.
 * @return a string in base64
 */
std::string EncodeToBase64(const std::string &data, bool url = false);

/**
 * Encode from bytes to base64
 * @param buf
 * @param buf_len
 * @param url use urlbase64 if 'url' is set true.
 * @return a string in base64
 */
std::string EncodeToBase64(unsigned char const* buf, size_t buf_len, bool url = false);

/**
 * Decode from base64 string to bytes.
 * @param base64
 * @param remove_linebreaks remove linebreaks if it's set true.
 * @return data in bytes
 */
std::string DecodeFromBase64(const std::string &base64, bool remove_linebreaks = false);

};
};
};

#endif //SAFEHERON_BASE64_H
