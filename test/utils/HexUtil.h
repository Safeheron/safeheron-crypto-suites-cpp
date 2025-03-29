//
// Created by Sword03 on 2025/3/29.
//

#ifndef SAFEHERONCRYPTOSUITES_TEST_UTILS_HEXUTILS_H_
#define SAFEHERONCRYPTOSUITES_TEST_UTILS_HEXUTILS_H_

#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>

#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace ssgx_test {
namespace utils {

inline std::string BytesToHex(const uint8_t* buf, size_t buf_len) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < buf_len; ++i) {
        oss << std::setw(2) << static_cast<int>(buf[i]);
    }
    return oss.str();
}

inline std::vector<uint8_t> HexToBytes(const char* str_ptr, size_t str_len) {
    if (str_len % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }

    auto HexCharToInt = [](char c) -> int {
        if ('0' <= c && c <= '9') return c - '0';
        if ('A' <= c && c <= 'F') return c - 'A' + 10;
        if ('a' <= c && c <= 'f') return c - 'a' + 10;
        throw std::invalid_argument("Invalid hex character in input");
    };

    std::vector<uint8_t> result;
    result.reserve(str_len / 2);

    for (size_t i = 0; i < str_len; i += 2) {
        int high = HexCharToInt(str_ptr[i]);
        int low = HexCharToInt(str_ptr[i + 1]);
        result.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    return result;
}

inline std::vector<uint8_t> HexToBytes(const std::string& str) {
    return HexToBytes(str.data(), str.size());
}

}  // namespace utils
}  // namespace ssgx_test


#endif // SAFEHERONCRYPTOSUITES_TEST_UTILS_HEXUTILS_H_
