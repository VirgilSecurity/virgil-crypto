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

#ifndef VIRGIL_CRYPTO_CONFIG_FILE
#include <virgil/crypto/config.h>
#else
#include VIRGIL_CRYPTO_CONFIG_FILE
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_BASE64_MODULE)

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <mbedtls/base64.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

std::string VirgilBase64::encode(const VirgilByteArray& data) {
    if (data.empty()) {
        return std::string();
    }
    // Define output length
    size_t bufLen = 0;
    const int returnCode = mbedtls_base64_encode(NULL, 0, &bufLen, data.data(), data.size());
    if (returnCode != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        system_crypto_handler(returnCode,
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );
    }
    // Encode
    VirgilByteArray buf(bufLen, '\0');
    system_crypto_handler(
            mbedtls_base64_encode(buf.data(), buf.size(), &bufLen, data.data(), data.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
    );
    // Return result
    buf.resize(bufLen);
    return VirgilByteArrayUtils::bytesToString(buf);
}

VirgilByteArray VirgilBase64::decode(const std::string& base64str) {
    if (base64str.empty()) {
        return VirgilByteArray();
    }
    const VirgilByteArray base64data = VirgilByteArrayUtils::stringToBytes(base64str);
    // Define output length
    size_t bufLen = 0;

    const int returnCode = mbedtls_base64_decode(NULL, 0, &bufLen, base64data.data(), base64data.size());
    if (returnCode != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        system_crypto_handler(returnCode,
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );
    }

    // Decode
    VirgilByteArray result(bufLen);
    system_crypto_handler(
            mbedtls_base64_decode(result.data(), bufLen, &bufLen, base64data.data(), base64data.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
    );
    // Return result
    result.resize(bufLen);
    return result;
}

#endif //VIRGIL_CRYPTO_FOUNDATION_BASE64_MODULE
