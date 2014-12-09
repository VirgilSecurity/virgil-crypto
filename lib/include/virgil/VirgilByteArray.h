/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef VIRGIL_BYTE_ARRAY_H
#define VIRGIL_BYTE_ARRAY_H

#include <string>
#include <vector>
#include <algorithm>

namespace virgil {

/**
 * @typedef VirgilByteArray
 * @brief This type represents a sequence of bytes.
 */
typedef std::vector<unsigned char> VirgilByteArray;

}

/**
 * @name ByteArray convertion utilities
 */
#define VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(array) reinterpret_cast<const unsigned char *>(array.data()), array.size()

#define VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(ptr, len)\
        virgil::VirgilByteArray(reinterpret_cast<virgil::VirgilByteArray::const_pointer>(ptr), \
        reinterpret_cast<virgil::VirgilByteArray::const_pointer>((ptr) + (len)))

inline virgil::VirgilByteArray virgil_byte_array_from_std_string(const std::string& str) {
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(str.data(), str.size());
}

inline std::string virgil_byte_array_to_std_string(const virgil::VirgilByteArray& array) {
    return std::string(reinterpret_cast<const char *>(array.data()), array.size());
}

#define VIRGIL_BYTE_ARRAY_FROM_STD_STRING(str) virgil_byte_array_from_std_string(str)
#define VIRGIL_BYTE_ARRAY_TO_STD_STRING(array) virgil_byte_array_to_std_string(array)
/**
 * @name ByteArray security clear utilities
 */
inline void virgil_byte_array_zeroize(virgil::VirgilByteArray& array) {
    std::fill(array.begin(), array.end(), 0);
}

#define VIRGIL_BYTE_ARRAY_ZEROIZE(array) virgil_byte_array_zeroize(array)
#endif /* VIRGIL_BYTE_ARRAY_H */
