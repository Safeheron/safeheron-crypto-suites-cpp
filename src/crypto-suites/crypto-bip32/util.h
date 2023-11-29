#ifndef _SAFEHERON_CRYPTOBIP32_UTIL_H
#define _SAFEHERON_CRYPTOBIP32_UTIL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t read_be(const uint8_t *data) {
    return (((uint32_t)data[0]) << 24) | (((uint32_t)data[1]) << 16) |
           (((uint32_t)data[2]) << 8) | (((uint32_t)data[3]));
}

static inline void write_be(uint8_t *data, uint32_t x) {
    data[0] = x >> 24;
    data[1] = x >> 16;
    data[2] = x >> 8;
    data[3] = x;
}

static inline uint32_t read_le(const uint8_t *data) {
    return (((uint32_t)data[3]) << 24) | (((uint32_t)data[2]) << 16) |
           (((uint32_t)data[1]) << 8) | (((uint32_t)data[0]));
}

static inline void write_le(uint8_t *data, uint32_t x) {
    data[3] = x >> 24;
    data[2] = x >> 16;
    data[1] = x >> 8;
    data[0] = x;
}

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif //_SAFEHERON_CRYPTOBIP32_UTIL_H
