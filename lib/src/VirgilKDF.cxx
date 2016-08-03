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

#define MODULE_NAME "VirgilKDF"

#include <virgil/crypto/foundation/VirgilKDF.h>

#include <mbedtls/kdf.h>
#include <mbedtls/oid.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/internal/utils.h>
#include <virgil/crypto/foundation/internal/mbedtls_type_utils.h>


using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;

using virgil::crypto::foundation::VirgilKDF;
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

/**
 * @name Configuration constants
 */
///@{
static constexpr char kHashType_Default[] = "SHA384";
///@}

namespace virgil { namespace crypto { namespace foundation {

class VirgilKDF::Impl {
public:
    Impl() : kdf_info(nullptr), md_info(nullptr) {}

    Impl(mbedtls_kdf_type_t kdf_type, mbedtls_md_type_t md_type) :
            kdf_info(mbedtls_kdf_info_from_type(kdf_type)),
            md_info(mbedtls_md_info_from_type(md_type)) {
        if (kdf_info == nullptr) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(kdf_type));
        }
        if (md_info == nullptr) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(md_type));
        }
    }

    Impl(const char* kdf_name, const char* md_name) :
            kdf_info(mbedtls_kdf_info_from_string(kdf_name)),
            md_info(mbedtls_md_info_from_string(md_name)) {
        if (kdf_info == nullptr) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, kdf_name);
        }
        if (md_info == nullptr) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, md_name);
        }
    }

public:
    mbedtls_kdf_info_t const* kdf_info; // KDF algorithm type info
    mbedtls_md_info_t const* md_info; // Hash algorithm type info
};

}}}


VirgilKDF::VirgilKDF() : impl_(std::make_unique<Impl>()) {
}

VirgilKDF::VirgilKDF(VirgilKDF::Algorithm alg)
        : impl_(std::make_unique<Impl>(std::to_string(alg).c_str(), kHashType_Default)) {
}

VirgilKDF::VirgilKDF(const std::string& name) : impl_(std::make_unique<Impl>(name.c_str(), kHashType_Default)) {
}

VirgilKDF::VirgilKDF(const char* name) : impl_(std::make_unique<Impl>(name, kHashType_Default)) {
}

VirgilKDF::~VirgilKDF() noexcept {}

VirgilKDF::VirgilKDF(VirgilKDF&& rhs) = default;

VirgilKDF& VirgilKDF::operator=(VirgilKDF&& rhs) = default;

std::string VirgilKDF::name() const {
    checkState();
    return std::string(mbedtls_kdf_get_name(impl_->kdf_info));
}


VirgilByteArray VirgilKDF::derive(const VirgilByteArray& in, size_t outSize) {
    checkState();
    VirgilByteArray result(outSize);
    system_crypto_handler(
            mbedtls_kdf(impl_->kdf_info, impl_->md_info, in.data(), in.size(), result.data(), result.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
    );
    return result;
}

void VirgilKDF::checkState() const {
    if (impl_->kdf_info == nullptr || impl_->md_info == nullptr) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
}

size_t VirgilKDF::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();

    size_t len = 0;
    const char* oid = 0;
    size_t oidLen;

    // Write hash algorithm identifier
    mbedtls_md_type_t mdType = mbedtls_md_get_type(impl_->md_info);
    system_crypto_handler(
            mbedtls_oid_get_oid_by_md(mdType, &oid, &oidLen),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );
    len += asn1Writer.writeNull();
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);

    // Write key derivation function algorithm identifier
    mbedtls_kdf_type_t kdfType = mbedtls_kdf_get_type(impl_->kdf_info);
    system_crypto_handler(
            mbedtls_oid_get_oid_by_kdf_alg(kdfType, &oid, &oidLen),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilKDF::asn1Read(VirgilAsn1Reader& asn1Reader) {
    // Read key derivation function algorithm identifier
    asn1Reader.readSequence();
    VirgilByteArray oid = VirgilByteArrayUtils::stringToBytes(asn1Reader.readOID());
    mbedtls_asn1_buf oidAsn1Buf;
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = oid.data();

    mbedtls_kdf_type_t kdfType = MBEDTLS_KDF_NONE;
    system_crypto_handler(
            mbedtls_oid_get_kdf_alg(&oidAsn1Buf, &kdfType),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );

    // Read hash algorithm identifier
    asn1Reader.readSequence();
    oid = VirgilByteArrayUtils::stringToBytes(asn1Reader.readOID());
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = oid.data();

    mbedtls_md_type_t mdType = MBEDTLS_MD_NONE;
    system_crypto_handler(
            mbedtls_oid_get_md_alg(&oidAsn1Buf, &mdType),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );

    asn1Reader.readNull();
    impl_ = std::make_unique<Impl>(kdfType, mdType);
}

std::string std::to_string(VirgilKDF::Algorithm alg) {
    switch (alg) {
        case VirgilKDF::Algorithm::KDF1:
            return "KDF1";
        case VirgilKDF::Algorithm::KDF2:
            return "KDF2";
    }
}
