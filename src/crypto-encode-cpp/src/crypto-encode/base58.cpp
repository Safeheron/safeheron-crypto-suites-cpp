// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include <string.h>
#include <stdexcept>
#include "base58_imp.h"

namespace safeheron {
namespace encode {
namespace base58 {

std::string EncodeToBase58(const std::string &data){
    std::vector<unsigned char> vch(data.begin(), data.end());
    return _internal::EncodeBase58(vch);
}
std::string EncodeToBase58(unsigned char const *buf, size_t buf_len){
    std::vector<unsigned char> vch(buf, buf + buf_len);
    return _internal::EncodeBase58(vch);
}

std::string DecodeFromBase58(const std::string &base58){
    std::vector<unsigned char> vch_ret;
    bool success = _internal::DecodeBase58(base58, vch_ret);
    if(!success) throw std::runtime_error("Failed in _internal::DecodeBase58.");
    std::string str_ret(vch_ret.begin(), vch_ret.end());
    return str_ret;
}


std::string EncodeToBase58Check(const std::string &data){
    std::vector<unsigned char> vch(data.begin(), data.end());
    return _internal::EncodeBase58Check(vch);
}

std::string EncodeToBase58Check(unsigned char const *buf, size_t buf_len){
    std::vector<unsigned char> vch(buf, buf + buf_len);
    return _internal::EncodeBase58Check(vch);
}

std::string DecodeFromBase58Check(const std::string &base58){
    std::vector<unsigned char> vch_ret;
    bool success = _internal::DecodeBase58Check(base58, vch_ret);
    if(!success) throw std::runtime_error("Failed in _internal::DecodeBase58.");
    std::string str_ret(vch_ret.begin(), vch_ret.end());
    return str_ret;
}

}
}
}
