//
// Created by Sword03 on 2023/9/13.
//

#ifndef SAFEHERONCRYPTOSUITES_ZKP_COMMON_H
#define SAFEHERONCRYPTOSUITES_ZKP_COMMON_H

#include <stdlib.h>
static void uint_to_byte4(uint8_t buf[4], unsigned int ui){
    // Big endian
    buf[3] = ui & 0x000000ff;
    buf[2] = (ui & 0x0000ff00) >> 8;
    buf[1] = (ui & 0x00ff0000) >> 16;
    buf[0] = (ui & 0xff000000) >> 24;

}

#endif //SAFEHERONCRYPTOSUITES_ZKP_COMMON_H
