/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#include "base64.h"
#include "base64_imp.h"

namespace safeheron {
namespace encode {
namespace base64 {

std::string EncodeToBase64(const std::string &data, bool url) {
    return _internal::base64_encode(data, url);
}

std::string EncodeToBase64(const unsigned char * buf, size_t buf_len, bool url){
    return _internal::base64_encode(buf, buf_len, url);
}

std::string DecodeFromBase64(const std::string &base64, bool remove_linebreaks) {
    return _internal::base64_decode(base64, remove_linebreaks);
}

};
};
};
