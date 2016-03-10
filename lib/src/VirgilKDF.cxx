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

#include <virgil/crypto/foundation/VirgilKDF.h>

#include <string>

#include <mbedtls/kdf.h>
#include <mbedtls/oid.h>
#include <mbedtls/kdf.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/PolarsslException.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Compatible.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;

using virgil::crypto::foundation::VirgilKDF;
using virgil::crypto::foundation::VirgilKDFImpl;
using virgil::crypto::foundation::PolarsslException;
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

/**
 * @name Configuration constants
 */
///@{
static const mbedtls_md_type_t kHashType_Default = MBEDTLS_MD_SHA256;
///@}

namespace virgil { namespace crypto { namespace foundation {

class VirgilKDFImpl {
public:
    VirgilKDFImpl() : kdfInfo(0), mdInfo(0)  {
    }

    VirgilKDFImpl(mbedtls_kdf_type_t kdfType, mbedtls_md_type_t mbedtls_md_type_t) : kdfInfo(0), mdInfo(0)  {
        kdfInfo = mbedtls_kdf_info_from_type(kdfType);
        mdInfo = mbedtls_md_info_from_type(mbedtls_md_type_t);
    }
public:
    mbedtls_kdf_info_t const * kdfInfo; // KDF algorithm type info
    mbedtls_md_info_t const *  mdInfo; // hash algorithm type info
};

}}}

VirgilKDF VirgilKDF::kdf1() {
    return VirgilKDF(MBEDTLS_KDF_KDF1, kHashType_Default);
}

VirgilKDF VirgilKDF::kdf2() {
    return VirgilKDF(MBEDTLS_KDF_KDF2, kHashType_Default);
}

VirgilKDF::VirgilKDF() : impl_(new VirgilKDFImpl()) {
}

VirgilKDF::VirgilKDF(int kdfType, int mdType)
        : impl_(new VirgilKDFImpl(static_cast<mbedtls_kdf_type_t>(kdfType), static_cast<mbedtls_md_type_t>(mdType))) {
}

VirgilKDF::~VirgilKDF() throw() {
    if (impl_) {
        delete impl_;
        impl_ = 0;
    }
}

VirgilKDF::VirgilKDF(const VirgilKDF& other) : impl_(new VirgilKDFImpl(*other.impl_)) {
}

VirgilKDF& VirgilKDF::operator=(const VirgilKDF& rhs) {
    if (this == &rhs) {
        return *this;
    }
    VirgilKDFImpl *newImpl = new VirgilKDFImpl(*rhs.impl_);
    if (impl_) {
        delete impl_;
    }
    impl_ = newImpl;
    return *this;
}

std::string VirgilKDF::name() const {
    checkState();
    return std::string(::mbedtls_kdf_get_name(impl_->kdfInfo));
}


VirgilByteArray VirgilKDF::derive(const VirgilByteArray& in, size_t outSize) {
    checkState();
    VirgilByteArray result(outSize);
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_kdf(impl_->kdfInfo, impl_->mdInfo, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(in), result.data(), result.size())
    );
    return result;
}

void VirgilKDF::checkState() const {
    if (impl_->kdfInfo == 0 || impl_->mdInfo == 0) {
        throw VirgilCryptoException(std::string("VirgilKDF: object has undefined algorithm.") +
                " Use one of the factory methods or method 'fromAsn1' to define key derivation function algorithm.");
    }
}

size_t VirgilKDF::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();

    size_t len = 0;
    const char *oid = 0;
    size_t oidLen;

    // Write hash algorithm identifier
    mbedtls_md_type_t mdType = ::mbedtls_md_get_type(impl_->mdInfo);
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_oid_by_md(mdType, &oid, &oidLen)
    );
    len += asn1Writer.writeNull();
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);

    // Write key derivation function algorithm identifier
    mbedtls_kdf_type_t kdfType = ::mbedtls_kdf_get_type(impl_->kdfInfo);
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_oid_by_kdf_alg(kdfType, &oid, &oidLen)
    );
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilKDF::asn1Read(VirgilAsn1Reader& asn1Reader) {
    mbedtls_asn1_buf oidAsn1Buf;
    std::string oid;

    // Read key derivation function algorithm identifier
    asn1Reader.readSequence();
    oid = asn1Reader.readOID();
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    mbedtls_kdf_type_t kdfType = MBEDTLS_KDF_NONE;
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_kdf_alg(&oidAsn1Buf, &kdfType)
    );

    // Read hash algorithm identifier
    asn1Reader.readSequence();
    oid = asn1Reader.readOID();
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    mbedtls_md_type_t mdType = MBEDTLS_MD_NONE;
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_md_alg(&oidAsn1Buf, &mdType)
    );

    asn1Reader.readNull();
    *this = VirgilKDF(kdfType, mdType);
}
