/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_HEX_CONV_H
#define SAFEHERON_HEX_CONV_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// tallymarker_hextobin
int tallymarker_hex2bin(const char *str, uint8_t *bytes, size_t blen);

int tallymarker_bin2hex(const uint8_t *bytes, size_t blen, char *str, size_t slen);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif //SAFEHERON_HEX_CONV_H
