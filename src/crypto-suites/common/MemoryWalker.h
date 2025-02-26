//
// Created by Sword03 on 2024/1/28.
//

#ifndef SAFEHERONCRYPTOSUITES_MEMORYWALKER_H
#define SAFEHERONCRYPTOSUITES_MEMORYWALKER_H

#include <cstdint>
#include <iostream>

namespace safeheron{
namespace memory{

class MemoryWalker {
public:
    MemoryWalker(const uint8_t * p_mem, int64_t mem_size){
        p_mem_ = p_mem;
        size_ = mem_size;

        p_cur_ = p_mem;
        left_ = mem_size;
    }

    bool move_byte(uint8_t &byte){
        uint32_t offset = sizeof(uint8_t);
        if(left_ < offset) return false;
        byte = p_cur_[0];
        p_cur_ += offset;
        left_ -= offset;
        return true;
    }

    bool move_uint32(uint32_t &ui){
        uint32_t offset = sizeof(uint32_t);
        if(left_ < offset) return false;
        ui = (p_cur_[0] << 24) +
             (p_cur_[1] << 16) +
             (p_cur_[2] << 8) +
             p_cur_[3] ;
        p_cur_ += offset;
        left_ -= offset;
        return true;
    }

    bool move_buf(const uint8_t * &buf, uint32_t buf_len) {
        uint32_t offset = buf_len;
        if(left_ < (int64_t)offset) return false;
        buf = p_cur_;
        p_cur_ += offset;
        left_ -= offset;
        return true;
    }

    const uint8_t * p_mem(){ return p_mem_; }

    const uint8_t * p_cur(){ return p_cur_; }

    int64_t size(){ return size_; }

    int64_t left(){ return left_; }

private:
    const uint8_t * p_mem_;
    int64_t size_;

    const uint8_t * p_cur_;
    int64_t left_;
};

}
}


#endif //SAFEHERONCRYPTOSUITES_MEMORYWALKER_H
