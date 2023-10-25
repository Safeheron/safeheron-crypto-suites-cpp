#ifndef __MEMZERO_H__
#define __MEMZERO_H__

#include <stddef.h>

void ed25519_donna_memzero(void* const pnt, const size_t len);

#endif
