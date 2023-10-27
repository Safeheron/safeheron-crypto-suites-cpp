//
// Created by Sword03 on 2022/7/17.
//

#ifndef CRYPTOBIP39_LANG_H
#define CRYPTOBIP39_LANG_H

#include <cstdint>

namespace safeheron {
namespace bip39 {

/**
 * Language
 */
enum class Language : uint32_t {
    ENGLISH = 0, /**< English. */
    SIMPLIFIED_CHINESE = 1, /**< Simplified Chinese */
    TRADITIONAL_CHINESE = 2, /**< Traditional Chinese */
};

}
}

#endif //CRYPTOBIP39_LANG_H
