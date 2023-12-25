#include "crypto-suites/crypto-hash/safe_hash512.h"

namespace safeheron{
namespace hash{

static const char hash_input_delimiter = '$';

static void uint_to_byte8(uint8_t buf[8], uint64_t ui){
    // Big endian
    buf[7] = ui & 0x00000000000000ff;
    buf[6] = (ui & 0x000000000000ff00) >> 8;
    buf[5] = (ui & 0x0000000000ff0000) >> 16;
    buf[4] = (ui & 0x00000000ff000000) >> 24;
    buf[3] = (ui & 0x000000ff00000000) >> 32;
    buf[2] = (ui & 0x0000ff0000000000) >> 40;
    buf[1] = (ui & 0x00ff000000000000) >> 48;
    buf[0] = (ui & 0xff00000000000000) >> 56;
}

void CSafeHash512::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    // Write (num)
    uint8_t byte8[8];
    uint_to_byte8(byte8, num);
    sha.Write( byte8, 8);

    sha.Finalize(hash);
}

CSafeHash512& CSafeHash512::Write(const unsigned char *data, size_t len) {
    // Write (data || delimiter || len ) instead of (data)
    uint8_t byte8[8];
    // Data
    sha.Write(data, len);
    // delimiter
    sha.Write( (const unsigned char*)&hash_input_delimiter, 1);
    // len
    uint_to_byte8(byte8, len);
    sha.Write( byte8, 8);

    ++num;
    return *this;
}

CSafeHash512& CSafeHash512::Reset() {
    sha.Reset();
    num = 0;
    return *this;
}


}
}

