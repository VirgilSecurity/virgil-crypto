/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#include <cstring>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <tuple>

namespace virgil { namespace crypto {

/**
 * @typedef VirgilByteArray
 * @brief This type represents a sequence of bytes.
 */
typedef std::vector<unsigned char> VirgilByteArray;

}}

/**
 * @name ByteArray conversation utilities
 */
/// @{
#define VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(array) reinterpret_cast<const unsigned char *>(array.data()), array.size()

#define VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(ptr, len)\
        virgil::crypto::VirgilByteArray(reinterpret_cast<virgil::crypto::VirgilByteArray::const_pointer >(ptr), \
        reinterpret_cast<virgil::crypto::VirgilByteArray::const_pointer >((ptr) + (len)))
///@}

namespace virgil { namespace crypto {

/**
 * @brief Represents given string as byte array.
 */
inline VirgilByteArray str2bytes(const std::string& str) {
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(str.data(), str.size());
}

/**
 * @brief Represent given byte array as string.
 */
inline std::string bytes2str(const VirgilByteArray& array) {
    return std::string(reinterpret_cast<const char*>(array.data()), array.size());
}

/**
 * @brief Translate given HEX string to the byte array.
 * @param hexStr - HEX string.
 * @return Byte array.
 */
inline VirgilByteArray hex2bytes(const std::string hexStr) {
    VirgilByteArray result;
    std::istringstream istr(hexStr);
    char hexChars[3] = {0x00};
    while (istr.read(hexChars, 2)) {
        int byte = 0;
        std::istringstream(hexChars) >> std::hex >> byte;
        result.push_back((unsigned char) byte);
    }
    return result;
}

/**
 * @brief Translate given byte array to the HEX string.
 * @param array - byte array.
 * @param formatted - if true, endline will be inserted every 16 bytes,
 *                    and all bytes will be separated with whitespaces.
 * @return HEX string.
 */
inline std::string bytes2hex(const VirgilByteArray& array, bool formatted = false) {
    std::ostringstream hexStream;
    hexStream << std::setfill('0');
    for (size_t i = 0; i < array.size(); ++i) {
        hexStream << std::hex << std::setw(2) << (int) array[i];
        if (formatted) {
            hexStream << (((i + 1) % 16 == 0) ? "\n" : " ");
        }
    }
    return hexStream.str();
}
/**
 * @name ByteArray security clear utilities
 */
///@{
/**
 * @brief Make all bytes zero.
 */
inline void bytes_zeroize(VirgilByteArray& array) {
    size_t n = array.size();
    volatile unsigned char* p = const_cast<unsigned char*>(array.data());
    while (n--) { *p++ = 0; }
}

/**
 * @brief Make all chars zero.
 */
inline void string_zeroize(std::string& str) {
    size_t n = str.size();
    volatile char* p = const_cast<char*>(str.c_str());
    while (n--) { *p++ = '\0'; }
}
///@}

/**
 * @brief Append given source bytes to the existing destination bytes.
 * @param dst - bytes append to.
 * @param src - bytes append from.
 * @return Reference to destination (dst).
 */
inline VirgilByteArray& bytes_append(VirgilByteArray& dst, const VirgilByteArray& src) {
    dst.insert(dst.end(), src.cbegin(), src.cend());
    return dst;
}

/**
 * @brief Split given bytes to two sequences.
 * @param src - bytes to be splitted.
 * @param pos - splitting position.
 * @return Two sequences: src[0, pos), src[pos, src.size()).
 */
inline std::tuple<VirgilByteArray, VirgilByteArray> bytes_split(const VirgilByteArray& src, size_t pos) {
    return std::make_tuple(
            VirgilByteArray(src.cbegin(), src.cbegin() + pos),
            VirgilByteArray(src.cbegin() + pos, src.cend()));
}

/**
 * @brief Split given bytes to two sequences of the same size.
 * @param src - bytes to be splitted.
 * @return Two sequences: src[0, src.size()/2), src[src.size()/2, src.size()).
 */
inline std::tuple<VirgilByteArray, VirgilByteArray> bytes_split_half(const VirgilByteArray& src) {
    const auto halfPos = src.size() >> 1;
    return bytes_split(src, halfPos);
}

/**
 * @brief Split given bytes to the chuns of the given size.
 * @param src - bytes to be splitted.
 * @param chunkSize - size of the chunk.
 * @return Chunks, each of the chunkSize.
 */
inline std::vector<VirgilByteArray> bytes_split_chunks(const VirgilByteArray& src, size_t chunkSize) {
    std::vector<VirgilByteArray> chunks;
    for (auto begin = src.cbegin(); begin < src.cend(); begin += chunkSize) {
        auto end = std::min(begin + chunkSize, src.end());
        chunks.emplace_back(VirgilByteArray(begin, end));
    }
    return chunks;
}

}}
#endif /* VIRGIL_BYTE_ARRAY_H */
