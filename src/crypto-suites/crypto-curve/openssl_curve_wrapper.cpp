#include <cassert>
#include <openssl/ec.h>
#include <cstring>
#include <memory>   // for std::unique_ptr
#include "crypto-suites/common/ByteArrayDeleter.h"
#include "crypto-suites/crypto-curve/openssl_curve_wrapper.h"
#include "crypto-suites/common/custom_assert.h"

using safeheron::common::ByteArrayDeleter;

namespace safeheron{
namespace _openssl_curve_wrapper {
int encode_ec_point(const ec_group_st* grp, const ec_point_st *pub,  uint8_t* pub_bytes, int pub_bytes_len, bool compress)
{
    int ret = 0;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;

    // clear output pub_bytes
    memset(pub_bytes, 0, pub_bytes_len);

    // check pointer is not null
    if(!pub || !pub_bytes) {
        ret = -1;
        goto err;
    }

    // check point is not infinity
    if (EC_POINT_is_at_infinity(grp, pub) == 1) {
        ret = -2;
        goto err;
    }

    if (!(bn_x = BN_new()) ||
        !(bn_y = BN_new())) {
        ret = -3;
        goto err;
    }

    if ((ret = EC_POINT_get_affine_coordinates(grp, pub, bn_x, bn_y, nullptr)) != 1) {
        ret = -4;
        goto err;
    }

    if (compress) {
        // For Secp256k1, P256, StarkCurve, pub_bytes_len = 33, coordinate_bytes_len = 32
        int coordinate_bytes_len = pub_bytes_len - 1;

        // temp buffer
        std::unique_ptr<uint8_t[], ByteArrayDeleter> tmp(new uint8_t[coordinate_bytes_len], ByteArrayDeleter(coordinate_bytes_len));
        memset(tmp.get(), 0, coordinate_bytes_len);

        // first byte
        if (BN_is_odd(bn_y)) {
            pub_bytes[0] = 0x03;
        } else {
            pub_bytes[0] = 0x02;
        }
        // encode x-coordinate
        if ((ret = BN_bn2binpad(bn_x, tmp.get(), coordinate_bytes_len)) != coordinate_bytes_len) {
            ret = -5;
            goto err;
        }
        // encode x in Big-Endian bytes
        uint8_t *des = pub_bytes + 1;
        memcpy(des, tmp.get(), coordinate_bytes_len);
        ret = 0;
    }
    else {
        // For Secp256k1, P256, StarkCurve, pub_bytes_len = 65, coordinate_bytes_len = 32
        int coordinate_bytes_len = (pub_bytes_len - 1)/2;

        // temp buffer
        std::unique_ptr<uint8_t[], ByteArrayDeleter> tmp(new uint8_t[coordinate_bytes_len], ByteArrayDeleter(coordinate_bytes_len));
        memset(tmp.get(), 0, coordinate_bytes_len);

        // First byte
        pub_bytes[0] = 0x04;
        // x-coordinate
        if ((ret = BN_bn2binpad(bn_x, tmp.get(), coordinate_bytes_len)) != coordinate_bytes_len) {
            ret = -6;
            goto err;
        }
        // encode x in Big-Endian bytes
        uint8_t *des = pub_bytes + 1;
        memcpy(des, tmp.get(), coordinate_bytes_len);
        // y-coordinate
        if ((ret = BN_bn2binpad(bn_y, tmp.get(), coordinate_bytes_len)) != coordinate_bytes_len) {
            ret = -7;
            goto err;
        }
        // encode y in Big-Endian bytes
        des = pub_bytes + 1 + coordinate_bytes_len;
        memcpy(des, tmp.get(), coordinate_bytes_len);
        ret = 0; // 0 is OK
    }

err:
    if (bn_x) {
        BN_clear_free(bn_x);
        bn_x = nullptr;
    }
    if (bn_y) {
        BN_clear_free(bn_y);
        bn_y = nullptr;
    }
    return ret;
}

}
}
