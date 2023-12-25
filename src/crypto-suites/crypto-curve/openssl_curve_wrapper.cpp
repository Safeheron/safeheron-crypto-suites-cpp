#include <cassert>
#include <openssl/ec.h>
#include <cstring>
#include "crypto-suites/crypto-curve/openssl_curve_wrapper.h"
#include "crypto-suites/common/custom_assert.h"

namespace safeheron{
namespace _openssl_curve_wrapper {
int encode_ec_point(const ec_group_st* grp, const ec_point_st *pub, uint8_t *pub_key, bool compress)
{
    int ret = 0;
    bool at_infinity = false;
    uint8_t tmp[64] = {0};
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;

    ASSERT_THROW(pub);
    ASSERT_THROW(pub_key);

    if (!(bn_x = BN_new()) ||
        !(bn_y = BN_new())) {
        goto err;
    }

    if (EC_POINT_is_at_infinity(grp, pub) == 1) {
        at_infinity = true;
    }

    if (!at_infinity) {
        if ((ret = EC_POINT_get_affine_coordinates(grp, pub, bn_x, bn_y, nullptr)) != 1) {
            ret = -1;
            goto err;
        }
    }
    else {
        BN_zero(bn_x);
        BN_zero(bn_y);
    }

    if (compress) {
        memset(pub_key, 0, 33);
        if (BN_is_odd(bn_y)) {
            pub_key[0] = 0x03;
        }
        else {
            pub_key[0] = 0x02;
        }
        if (!at_infinity) {
            if ((ret = BN_bn2bin(bn_x, tmp)) == 0) {
                ret = -1;
                goto err;
            }
            if (ret < 32) {
                uint8_t *des = pub_key + 33 - ret;
                memcpy(des, tmp, ret);
            } else {
                uint8_t *src = tmp + ret - 32;
                memcpy(pub_key + 1, src, 32);
            }
        }
        ret = 0;
    }
    else {
        memset(pub_key, 0, 65);
        pub_key[0] = 0x04;
        //
        if (!at_infinity) {
            if ((ret = BN_bn2bin(bn_x, tmp)) == 0) {
                ret = -1;
                goto err;
            }
            if (ret < 32) {
                uint8_t *des = pub_key + 33 - ret;
                memcpy(des, tmp, ret);
            } else {
                uint8_t *src = tmp + ret - 32;
                memcpy(pub_key + 1, src, 32);
            }
            //
            if ((ret = BN_bn2bin(bn_y, tmp)) == 0) {
                ret = -1;
                goto err;
            }
            if (ret < 32) {
                uint8_t *des = pub_key + (33+32) - ret;
                memcpy(des, tmp, ret);
            } else {
                uint8_t *src = tmp + ret - 32;
                memcpy(pub_key + 33, src, 32);
            }
        }

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

// priv_key is a 32 byte big endian stored number
// sig is 64 bytes long array for the signature
// digest is 32 bytes of digest
int sign_digest(const ec_group_st* grp, const uint8_t *priv_key, const uint8_t *digest32, uint8_t *sig64)
{
    int ret = 0;
    uint8_t tmp[32] = {0};
    BIGNUM* priv = nullptr;
    const BIGNUM* sig_r = nullptr;
    const BIGNUM* sig_s = nullptr;
    EC_KEY* ec_key = nullptr;
    ECDSA_SIG* ecdsa_sig = nullptr;
    const int MAX_TRY_TIMES = 10000;

    ASSERT_THROW(grp);
    ASSERT_THROW(priv_key && digest32 && sig64);

    if (!(priv = BN_new()) ||
        !(ec_key = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(grp)))) {
        ret = 1;
        goto err;
    }

    if (!BN_bin2bn(priv_key, 32, priv) ||
        (ret = EC_KEY_set_private_key(ec_key, priv)) != 1) {
        ret = 1;
        goto err;
    }

    if (!(ecdsa_sig = ECDSA_do_sign(digest32, 32, ec_key))) {
        ret = 2;
        goto err;
    }

    if (!(sig_r = ECDSA_SIG_get0_r(ecdsa_sig)) ||
        !(sig_s = ECDSA_SIG_get0_s(ecdsa_sig))) {
        ret = 2;
        goto err;
    }

    memset(sig64, 0, 64);

    // get r bytes
    if ((ret = BN_bn2bin(sig_r, tmp)) <= 0) {
        ret = 2;
        goto err;
    }
    if (ret < 32) {
        uint8_t *des = sig64 + (32 - ret);
        memcpy(des, tmp, ret);
    } else {
        uint8_t *src = tmp + (ret - 32);
        memcpy(sig64, src, 32);
    }

    // get s bytes
    if ((ret = BN_bn2bin(sig_s, tmp)) <= 0) {
        ret = 2;
        goto err;
    }
    if (ret < 32) {
        uint8_t *des = (sig64 + 32) + (32 - ret);
        memcpy(des, tmp, ret);
    } else {
        uint8_t *src = tmp + (ret - 32);
        memcpy((sig64 + 32), src, 32);
    }

    ret = 0;
    
err:
    if (ecdsa_sig) {
        ECDSA_SIG_free(ecdsa_sig);
        ecdsa_sig = nullptr;
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }
    if (priv) {
        BN_clear_free(priv);
        priv = nullptr;
    }
    return ret;
}

// pub_key is a 65 byte big endian stored number
// sig is 64 bytes long array for the signature
// digest is 32 bytes of digest
// returns 0 if verification succeeded
int verify_digest(const ec_group_st* grp, const uint8_t *pub_key, const uint8_t *digest32, const uint8_t *sig64)
{
    int ret = 0;
    EC_POINT* pub = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;
    BIGNUM* bn_r = nullptr;
    BIGNUM* bn_s = nullptr;
    BN_CTX* ctx = nullptr;
    EC_KEY* ec_key = nullptr;
    ECDSA_SIG* ecdsa_sig = nullptr;

    ASSERT_THROW(grp);
    ASSERT_THROW(pub_key && sig64 && digest32 );

    // only support uncompress public key
    if (pub_key[0] != 0x04) {
        return 1;
    }

    if (!(pub = EC_POINT_new(grp))) {
        ret = 1;
        goto err;
    }

    if (!(ctx = BN_CTX_new())) {
        ret = 1;
        goto err;
    }

    // bn_x and bn_y will be freed where BN_CTX_end() is called.
    BN_CTX_start(ctx);
    if (!(bn_x = BN_CTX_get(ctx)) ||
        !(bn_y = BN_CTX_get(ctx))) {
        ret = 1;
        goto err;
    }
    
    if (!BN_bin2bn(pub_key+1, 32, bn_x) ||
        !BN_bin2bn(pub_key+33, 32, bn_y) ||
        (ret = EC_POINT_set_affine_coordinates(grp, pub, bn_x, bn_y, ctx)) != 1) {
        ret = 1;
        goto err;
    }
    if (!(ec_key = EC_KEY_new()) ||
        (ret = EC_KEY_set_group(ec_key, grp)) != 1 ||
        (ret = EC_KEY_set_public_key(ec_key, pub)) != 1) {
        ret = 1;
        goto err;
    }

    // bn_r and bn_s will be freed where ECDSA_SIG_free() is called.
    if (!(bn_r = BN_new()) ||
        !(bn_s = BN_new())) {
        ret = 1;
        goto err;
    }

    if (!BN_bin2bn(sig64, 32, bn_r) ||
        !BN_bin2bn(sig64 + 32, 32, bn_s) ||
        !(ecdsa_sig = ECDSA_SIG_new()) ||
        (ret = ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s)) != 1) {
        ret = 1;
        goto err;
    }

    if ((ret = ECDSA_do_verify(digest32, 32, ecdsa_sig, ec_key)) != 1) {
        ret = 1;
        goto err;
    }

    ret = 0;    //OK
    
err:
    if (ecdsa_sig) {
        ECDSA_SIG_free(ecdsa_sig);
        ecdsa_sig = nullptr;
    }
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        ctx = nullptr;
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }
    if (pub) {
        EC_POINT_free(pub);
        pub = nullptr;
    }

    return ret;
}

}
}
