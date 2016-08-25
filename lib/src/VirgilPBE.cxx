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

#define MODULE_NAME "VirgilPBE"

#include <virgil/crypto/foundation/VirgilPBE.h>

#include <map>

#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/pkcs12.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
#include <virgil/crypto/foundation/asn1/internal/VirgilAsn1Alg.h>

#include <virgil/crypto/internal/utils.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCryptoException;

using virgil::crypto::foundation::VirgilPBE;
using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;
using virgil::crypto::foundation::asn1::internal::VirgilAsn1Alg;

namespace virgil { namespace crypto { namespace foundation { namespace internal {

/**
 * @brief Throw exception if password is too long.
 * @note MbedTLS PKCS#12 restriction.
 */
static inline void check_pkcs12_pwd_len(size_t pwdLen) {
    const size_t kPasswordLengthMax = 31;
    if (pwdLen > kPasswordLengthMax) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Password too long. Max size is 31 bytes.");
    }
}

}}}}

class VirgilPBE::Impl {
public:
    bool initialized = false;
    VirgilPBE::Algorithm algorithm;
    VirgilByteArray algId;
    mbedtls_asn1_buf pbeAlgOID;
    mbedtls_asn1_buf pbeParams;
    mbedtls_md_type_t mdType;
    mbedtls_cipher_type_t cipherType;
public:
    Impl() : initialized(false) {}

    Impl(VirgilPBE::Algorithm pbeType, const VirgilByteArray& salt, size_t iterationCount)
            : initialized(false), algorithm(pbeType) {
        const size_t adjustedIterationCount =
                iterationCount < VirgilPBE::kIterationCountMin ? iterationCount + VirgilPBE::kIterationCountMin
                                                               : iterationCount;
        switch (pbeType) {
            case VirgilPBE::Algorithm::PKCS5:
                init_(VirgilAsn1Alg::buildPKCS5(salt, adjustedIterationCount));
                break;
            case VirgilPBE::Algorithm::PKCS12:
                init_(VirgilAsn1Alg::buildPKCS12(salt, adjustedIterationCount));
                break;
        }
    }

    Impl(const VirgilByteArray& pbeAlgId) : initialized(false) {
        init_(pbeAlgId);
    }

private:
    /**
     * @brief Parse given PBE algorithm identifier and stores parsed data as local object state.
     * @note Algorithm identifier is distributed in ASN.1 DER encoded structure:
     *     AlgorithmIdentifier ::= SEQUENCE {
     *         algorithm OBJECT IDENTIFIER,
     *         parameters ANY DEFINED BY algorithm OPTIONAL }
     * @throw VirgilCryptoException if algorithm identifier is not supported or ASN.1 structure is corrupted.
     */
    void init_(const VirgilByteArray& pbeAlgId) {

        // Initial init
        initialized = false;
        algId = pbeAlgId;
        mdType = MBEDTLS_MD_NONE;
        cipherType = MBEDTLS_CIPHER_NONE;
        std::memset(&pbeAlgOID, 0x00, sizeof(pbeAlgOID));
        std::memset(&pbeParams, 0x00, sizeof(pbeParams));

        // Parse ASN.1
        unsigned char* p = algId.data();
        unsigned char* end = p + algId.size();

        system_crypto_handler(
                mbedtls_asn1_get_alg(&p, end, &pbeAlgOID, &pbeParams),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );

        if (mbedtls_oid_get_pkcs12_pbe_alg(&pbeAlgOID, &mdType, &cipherType) == 0) {
            algorithm = VirgilPBE::Algorithm::PKCS12;
        } else if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS5_PBES2, &pbeAlgOID) == 0) {
            algorithm = VirgilPBE::Algorithm::PKCS5;
        } else {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
        }
        initialized = true;
    }
};

VirgilPBE::VirgilPBE() : impl_(std::make_unique<Impl>()) {}

VirgilPBE::VirgilPBE(Algorithm alg, const VirgilByteArray& salt, size_t iterationCount)
        : impl_(std::make_unique<Impl>(alg, salt, iterationCount)) {

}

VirgilPBE::VirgilPBE(VirgilPBE&& rhs) noexcept = default;

VirgilPBE& VirgilPBE::operator=(VirgilPBE&& rhs) noexcept = default;

VirgilPBE::~VirgilPBE() noexcept = default;

VirgilByteArray VirgilPBE::encrypt(const VirgilByteArray& data, const VirgilByteArray& pwd) const {
    int mode = (impl_->algorithm == VirgilPBE::Algorithm::PKCS5) ? MBEDTLS_PKCS5_ENCRYPT : MBEDTLS_PKCS12_PBE_ENCRYPT;
    return process(data, pwd, mode);
}

VirgilByteArray VirgilPBE::decrypt(const VirgilByteArray& data, const VirgilByteArray& pwd) const {
    int mode = (impl_->algorithm == VirgilPBE::Algorithm::PKCS5) ? MBEDTLS_PKCS5_DECRYPT : MBEDTLS_PKCS12_PBE_DECRYPT;
    return process(data, pwd, mode);
}

VirgilByteArray VirgilPBE::process(const VirgilByteArray& data, const VirgilByteArray& pwd, int mode) const {
    checkState();
    VirgilByteArray output(data.size() + MBEDTLS_MAX_BLOCK_LENGTH);
    mbedtls_asn1_buf pbeParams = impl_->pbeParams;
    size_t olen = data.size(); // For RC4: output length = input length
    switch (impl_->algorithm) {
        case VirgilPBE::Algorithm::PKCS5:
            system_crypto_handler(
                    mbedtls_pkcs5_pbes2_ext(&pbeParams, mode, pwd.data(), pwd.size(), data.data(), data.size(),
                            output.data(), &olen),
                    [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
            );
            break;
        case VirgilPBE::Algorithm::PKCS12:
            internal::check_pkcs12_pwd_len(pwd.size());
            system_crypto_handler(
                    mbedtls_pkcs12_pbe_ext(&pbeParams, mode,
                            impl_->cipherType, impl_->mdType, pwd.data(), pwd.size(), data.data(), data.size(),
                            output.data(), &olen),
                    [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
            );
            break;
    }
    output.resize(olen);
    return output;
}

void VirgilPBE::checkState() const {
    if (!impl_->initialized) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
}

size_t VirgilPBE::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    size_t len = asn1Writer.writeData(impl_->algId);
    return len + childWrittenBytes;
}

void VirgilPBE::asn1Read(VirgilAsn1Reader& asn1Reader) {
    impl_ = std::make_unique<Impl>(asn1Reader.readData());
}
