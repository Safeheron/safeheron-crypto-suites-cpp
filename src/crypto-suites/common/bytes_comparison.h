#ifndef SAFEHERONCRYPTOSUITES_BYTES_COMPARISON_H
#define SAFEHERONCRYPTOSUITES_BYTES_COMPARISON_H
#include <string>
namespace safeheron {
namespace common {
inline bool BytesEqual(const std::string &buf1, const std::string &buf2) {
    size_t len1 = buf1.size();
    size_t len2 = buf2.size();

    if (len1 != len2) return false;

    return memcmp(buf1.c_str(), buf2.c_str(), len1) == 0;
}

inline bool BytesEqual(const uint8_t* buf1, size_t len1, const uint8_t* buf2, size_t len2) {
    if (len1 != len2) return false;
    return memcmp(buf1, buf2, len1) == 0;
}

inline bool BytesEqual(const std::string &buf1, const uint8_t* buf2, size_t len2) {
    if (buf1.size() != len2) return false;
    return memcmp(buf1.c_str(), buf2, len2) == 0;
}

// inline bool IsBytesEqualCT(const std::string &buffer1, const std::string &buffer2) {
//     if (buffer1.size() != buffer2.size()) return false;
//
//     unsigned char diff = 0;
//     for (size_t i = 0; i < buffer1.size(); ++i) {
//         diff |= (unsigned char)buffer1[i] ^ (unsigned char)buffer2[i];
//     }
//     return diff == 0;
// }

}
}
#endif //SAFEHERONCRYPTOSUITES_BYTES_COMPARISON_H