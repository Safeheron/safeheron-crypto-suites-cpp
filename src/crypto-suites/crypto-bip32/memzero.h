#ifndef __SAFEHERON_CRYPTOBIP32_MEMZERO_H__
#define __SAFEHERON_CRYPTOBIP32_MEMZERO_H__

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

void crypto_bip32_memzero(void* const pnt, const size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif //__SAFEHERON_CRYPTOBIP32_MEMZERO_H__
