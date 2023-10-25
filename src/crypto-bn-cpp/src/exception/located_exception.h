#ifndef SAFEHERON_LOCATED_EXCEPTION_H
#define SAFEHERON_LOCATED_EXCEPTION_H

#define EXCEPTION_BUF_SIZE_FILE_PATH 48
#define EXCEPTION_BUF_SIZE_FUNC 24
#define EXCEPTION_BUF_SIZE_MESSAGE 128

#include <string.h>
#include <stdexcept>

namespace safeheron{
namespace exception{

/**
 * LocatedException class thrown with extra information such as file_path, func, line_num, internal_code and descriptions.
 *
 * \code{.cpp}
 *    try {
 *          if ((ret = BN_set_bit(bn_, index)) != 1) {
 *            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_set_bit(bn_, index)) != 1");
 *          }
 *    } catch (const LocatedException &e) {
 *          std::cout << e.what() << std::endl;
 *    }
 * \endcode
 *
 * The output is:
 *      Catch LocatedException: tring_crypto/crypto-bn-cpp/src/crypto-bn/bn.cpp:1124:FromBytesBE:0:(ret = BN_set_bit(bn_, index)) != 1
 */
class LocatedException : public std::exception
{
public:
    explicit LocatedException(const char * file_path, int line_num, const char * func, int internal_code, const char * message) {
        info_.reserve(EXCEPTION_BUF_SIZE_FILE_PATH + EXCEPTION_BUF_SIZE_FUNC + EXCEPTION_BUF_SIZE_MESSAGE + 30);

        int src_offset = 0;
        size_t src_len = strlen(file_path);
        if(src_len >= EXCEPTION_BUF_SIZE_FILE_PATH){
            src_offset = src_len - EXCEPTION_BUF_SIZE_FILE_PATH + 1;
            src_len = EXCEPTION_BUF_SIZE_FILE_PATH - 1;
        }
        info_.append(file_path + src_offset, src_len);
        info_.append(":");

        info_.append(std::to_string(line_num));
        info_.append(":");

        src_offset = 0;
        src_len = strlen(func);
        if(src_len >= EXCEPTION_BUF_SIZE_FUNC){
            src_offset = src_len - EXCEPTION_BUF_SIZE_FUNC + 1;
            src_len = EXCEPTION_BUF_SIZE_FUNC - 1;
        }
        info_.append(func + src_offset, src_len);
        info_.append(":");

        info_.append(std::to_string(internal_code));
        info_.append(":");

        src_offset = 0;
        src_len = strlen(message);
        if(src_len >= EXCEPTION_BUF_SIZE_MESSAGE){
            src_offset = src_len - EXCEPTION_BUF_SIZE_MESSAGE + 1;
            src_len = EXCEPTION_BUF_SIZE_MESSAGE - 1;
        }
        info_.append(message + src_offset, src_len);
    }

    virtual const char* what() const throw () {
        return info_.c_str();
    }

public:
    std::string info_;
};

};
};

#endif // SAFEHERON_LOCATED_EXCEPTION_H
