//
// Created by Sword03 on 2024/1/28.
//

#ifndef SAFEHERONCRYPTOSUITES_MEMORYWRITER_H
#define SAFEHERONCRYPTOSUITES_MEMORYWRITER_H

#include <cstdint>
#include <memory>
#include <cstring>

namespace safeheron{
namespace memory{

class MemoryWriter {
public:
    MemoryWriter(uint8_t * p_mem, int64_t mem_size){
        p_mem_ = p_mem;
        p_cur_ = p_mem;
        size_ = mem_size;
        left_ = mem_size;
    }

    bool write_byte(uint8_t byte){
        uint32_t offset = sizeof(uint8_t);
        if(left_ < offset) return false;
        p_cur_[0] = byte;
        p_cur_ += offset;
        left_ -= offset;
        return true;
    }

    bool write_uint32(uint32_t ui){
        uint32_t offset = sizeof(uint32_t);
        if(left_ < offset) return false;
        p_cur_[0] = ui >> 24;
        p_cur_[1] = ui >> 16;
        p_cur_[2] = ui >> 8;
        p_cur_[3] = ui;
        p_cur_ += offset;
        left_ -= offset;
        return true;
    }

    bool write_buf(const uint8_t * buf, uint32_t buf_len){
        uint32_t offset = buf_len;
        if(left_ < (int64_t)offset) return false;
        memcpy(p_cur_, buf, buf_len);
        p_cur_ += offset;
        left_ -= offset;
        return true;
    }

    const uint8_t * p_mem(){ return p_mem_; }

    const uint8_t * p_cur(){ return p_cur_; }

    int64_t size(){ return size_; }

    int64_t left(){ return left_; }

private:
    uint8_t * p_mem_;
    int64_t size_;

    uint8_t * p_cur_;
    int64_t left_;
};

}
}

#endif //SAFEHERONCRYPTOSUITES_MEMORYWRITER_H
