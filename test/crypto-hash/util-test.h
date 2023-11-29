//
// Created by Sword03 on 2020/10/22.
//
#include <memory>

std::string bytes2hex(const uint8_t * input, size_t input_len){
    static const char *sha2_hex_digits = "0123456789abcdef";
    std::unique_ptr<char[]> output_hex(new char [input_len * 2 + 1]);
    const uint8_t *d = input;
    for (size_t i = 0; i < input_len; i++) {
        output_hex[i * 2] = sha2_hex_digits[(*d & 0xf0) >> 4];
        output_hex[i * 2 + 1] = sha2_hex_digits[*d & 0x0f];
        d++;
    }
    output_hex[input_len * 2] = (char)0;
    std::string ret;
    ret.assign(output_hex.get());
    return ret;
}