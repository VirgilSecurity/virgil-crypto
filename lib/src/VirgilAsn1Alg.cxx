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

#define MODULE_NAME "VirgilAsn1Alg"

#include <virgil/crypto/foundation/asn1/internal/VirgilAsn1Alg.h>

#include <mbedtls/oid.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::asn1::internal::VirgilAsn1Alg;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

VirgilByteArray VirgilAsn1Alg::buildPKCS5(const VirgilByteArray& salt, size_t iterationCount) {
    VirgilRandom random(VirgilByteArrayUtils::stringToBytes("pkcs5_seed"));
    VirgilAsn1Writer asn1Writer;
    const char* oid = 0;
    size_t oidLen;
    // Write PBES2-params
    size_t pbesLen = 0;
    {
        // Write PBES2-Enc
        const mbedtls_cipher_type_t cipherType = MBEDTLS_CIPHER_AES_256_CBC;
        system_crypto_handler(
                mbedtls_oid_get_oid_by_cipher_alg(cipherType, &oid, &oidLen),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
        const mbedtls_cipher_info_t* cipherInfo = mbedtls_cipher_info_from_type(cipherType);
        if (cipherInfo == nullptr) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
        }
        size_t encLen = 0;
        encLen += asn1Writer.writeOctetString(random.randomize(cipherInfo->iv_size));
        encLen += asn1Writer.writeOID(std::string(oid, oidLen));
        encLen += asn1Writer.writeSequence(encLen);

        // Write PBES2-KDF
        size_t prfLen = 0;
        prfLen += asn1Writer.writeOID(std::string(MBEDTLS_OID_HMAC_SHA384, MBEDTLS_OID_SIZE(MBEDTLS_OID_HMAC_SHA384)));
        prfLen += asn1Writer.writeSequence(prfLen);

        size_t kdfLen = prfLen;
        kdfLen += asn1Writer.writeInteger(iterationCount);
        kdfLen += asn1Writer.writeOctetString(salt);
        kdfLen += asn1Writer.writeSequence(kdfLen);
        kdfLen +=
                asn1Writer.writeOID(std::string(MBEDTLS_OID_PKCS5_PBKDF2, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBKDF2)));
        kdfLen += asn1Writer.writeSequence(kdfLen);

        pbesLen += encLen + kdfLen;
        pbesLen += asn1Writer.writeSequence(pbesLen);
    }
    // Write id-PBES2 OBJECT IDENTIFIER
    pbesLen += asn1Writer.writeOID(std::string(MBEDTLS_OID_PKCS5_PBES2, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBES2)));
    asn1Writer.writeSequence(pbesLen);

    return asn1Writer.finish();
}

VirgilByteArray VirgilAsn1Alg::buildPKCS12(const VirgilByteArray& salt, size_t iterationCount) {
    VirgilAsn1Writer asn1Writer;
    // Write PBE-params
    size_t pbesLen = 0;
    pbesLen += asn1Writer.writeInteger(iterationCount);
    pbesLen += asn1Writer.writeOctetString(salt);
    pbesLen += asn1Writer.writeSequence(pbesLen);
    // Write id-PBE OBJECT IDENTIFIER
    pbesLen += asn1Writer.writeOID(
            std::string(MBEDTLS_OID_PKCS12_PBE_SHA1_DES3_EDE_CBC,
                    MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS12_PBE_SHA1_DES3_EDE_CBC)));
    asn1Writer.writeSequence(pbesLen);

    return asn1Writer.finish();
}
