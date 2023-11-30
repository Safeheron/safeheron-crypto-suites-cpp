#include "crypto-suites/crypto-hash/safe_hash256.h"

namespace safeheron{
namespace hash{

static const char hash_input_delimiter = '$';

static void uint_to_byte4(uint8_t buf[4], unsigned int ui){
    // Big endian
    buf[3] = ui & 0x000000ff;
    buf[2] = (ui & 0x0000ff00) >> 8;
    buf[1] = (ui & 0x00ff0000) >> 16;
    buf[0] = (ui & 0xff000000) >> 24;
}

void CSafeHash256::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    // Write (num)
    uint8_t byte4[4];
    uint_to_byte4(byte4, num);
    sha.Write( byte4, 4);

    sha.Finalize(hash);
}

CSafeHash256& CSafeHash256::Write(const unsigned char *data, size_t len) {
    // Write (data || delimiter || len ) instead of (data)
    uint8_t byte4[4];
    // Data
    sha.Write(data, len);
    // delimiter
    sha.Write( (const unsigned char*)&hash_input_delimiter, 1);
    // len
    uint_to_byte4(byte4, len);
    sha.Write( byte4, 4);

    ++ num;
    return *this;
}

CSafeHash256& CSafeHash256::Reset() {
    sha.Reset();
    num = 0;
    return *this;
}


}
}

