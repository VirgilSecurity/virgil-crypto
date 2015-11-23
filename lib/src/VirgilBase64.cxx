/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <string>

#include <polarssl/base64.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/PolarsslException.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;
using virgil::crypto::foundation::PolarsslException;

std::string VirgilBase64::encode(const VirgilByteArray& data) {
    if (data.empty()) {
        return std::string();
    }
    // Define output length
    size_t bufLen = 0;
    ::base64_encode(NULL, &bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data));
    // Encode
    unsigned char *buf = new unsigned char[bufLen];
    ::base64_encode(buf, &bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data));
    // Return result
    std::string result(reinterpret_cast<const char *>(buf), bufLen);
    delete[] buf;
    return result;
}

VirgilByteArray VirgilBase64::decode(const std::string& base64str) {
    if (base64str.empty()) {
        return VirgilByteArray();
    }
    // Define output length
    size_t bufLen = 0;
    ::base64_decode(NULL, &bufLen, reinterpret_cast<const unsigned char *>(base64str.data()), base64str.size());
    // Decode
    VirgilByteArray result(bufLen);
    ::base64_decode(result.data(), &bufLen,
            reinterpret_cast<const unsigned char *>(base64str.data()), base64str.size());
    // Return result
    return result;
}
