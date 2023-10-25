#include "hd_path.h"

namespace safeheron {
namespace bip32 {

bool HDPath::ParseHDPath(const std::string &keypath_str, std::vector<uint32_t> &keypath) {
    std::string item;
    std::string::size_type start = 0;
    std::string::size_type end = 0;
    if(keypath_str.length() == 0) return false;
    // return false if it ends with '/'
    if(keypath_str.at(keypath_str.length() - 1) == '/') return false;
    bool first = true;
    while (end != std::string::npos) {
        if((end = keypath_str.find('/', start)) != std::string::npos) {
            item = keypath_str.substr(start, end - start);
        } else{
            item = keypath_str.substr(start);
        }
        start = end + 1;
        if (item == "") return false;

        if (first) {
            first = false;
            if (item.compare("m") == 0 || item.compare("M") == 0) {
                continue;
            } else {
                return false;
            }
        }

        // Finds whether it is hardened
        uint32_t path = 0;
        size_t pos = item.find('\'');
        if (pos != std::string::npos) {
            // The hardened tick can only be in the last index of the string
            if (pos != item.size() - 1) {
                return false;
            }
            path |= 0x80000000;
            item = item.substr(0, item.size() - 1); // Drop the last character which is the hardened tick
        }

        // Ensure this is only numbers
        if (item.find_first_not_of("0123456789") != std::string::npos) {
            return false;
        }
        uint32_t number;
        char *ptr = nullptr;
        number = strtoul(item.c_str(), &ptr, 10);

        if (number > 0x80000000) return false;

        path |= number;

        keypath.push_back(path);
        first = false;
    }
    return true;
}

std::string HDPath::FormatHDPath(const std::vector<uint32_t> &path) {
    std::string str;
    for (auto i : path) {
        str.append("/");
        str.append(std::to_string(i & 0x7fffffff));
        if (i >> 31) str.append("\'");
    }
    return str;
}

std::string HDPath::WriteHDPath(const std::vector<uint32_t> &keypath) {
    return "m" + FormatHDPath(keypath);
}

}
}
