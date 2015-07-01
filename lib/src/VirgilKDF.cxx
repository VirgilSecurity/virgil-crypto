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

#include <virgil/crypto/foundation/VirgilKDF.h>
using virgil::crypto::foundation::VirgilKDF;
using virgil::crypto::foundation::VirgilKDFImpl;

#include <polarssl/kdf.h>
#include <polarssl/oid.h>
#include <polarssl/kdf.h>

#include <virgil/crypto/VirgilByteArray.h>
using virgil::crypto::VirgilByteArray;

#include <virgil/crypto/foundation/PolarsslException.h>
using virgil::crypto::foundation::PolarsslException;

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/foundation/asn1/VirgilAsn1Compatible.h>
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;

#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;

#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

#include <string>

/**
 * @name Configuration constants
 */
///@{
static const md_type_t kHashType_Default = POLARSSL_MD_SHA256;
///@}

namespace virgil { namespace crypto { namespace foundation {

class VirgilKDFImpl {
public:
    VirgilKDFImpl() : kdfInfo(0), mdInfo(0)  {
    }

    VirgilKDFImpl(kdf_type_t kdfType, md_type_t md_type_t) : kdfInfo(0), mdInfo(0)  {
        kdfInfo = kdf_info_from_type(kdfType);
        mdInfo = md_info_from_type(md_type_t);
    }
public:
    kdf_info_t const * kdfInfo; // KDF algorithm type info
    md_info_t const *  mdInfo; // hash algorithm type info
};

}}}

VirgilKDF VirgilKDF::kdf1() {
    return VirgilKDF(POLARSSL_KDF_KDF1, kHashType_Default);
}

VirgilKDF VirgilKDF::kdf2() {
    return VirgilKDF(POLARSSL_KDF_KDF2, kHashType_Default);
}

VirgilKDF::VirgilKDF() : impl_(new VirgilKDFImpl()) {
}

VirgilKDF::VirgilKDF(int kdfType, int mdType)
        : impl_(new VirgilKDFImpl(static_cast<kdf_type_t>(kdfType), static_cast<md_type_t>(mdType))) {
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
    return std::string(::kdf_get_name(impl_->kdfInfo));
}


VirgilByteArray VirgilKDF::derive(const VirgilByteArray& in, size_t outSize) {
    checkState();
    VirgilByteArray result(outSize);
    POLARSSL_ERROR_HANDLER(
        ::kdf(impl_->kdfInfo, impl_->mdInfo, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(in), result.data(), result.size())
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
    md_type_t mdType = ::md_get_type(impl_->mdInfo);
    POLARSSL_ERROR_HANDLER(
        ::oid_get_oid_by_md(mdType, &oid, &oidLen)
    );
    len += asn1Writer.writeNull();
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);

    // Write key derivation function algorithm identifier
    kdf_type_t kdfType = ::kdf_get_type(impl_->kdfInfo);
    POLARSSL_ERROR_HANDLER(
        ::oid_get_oid_by_kdf_alg(kdfType, &oid, &oidLen)
    );
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilKDF::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1_buf oidAsn1Buf;
    std::string oid;

    // Read key derivation function algorithm identifier
    asn1Reader.readSequence();
    oid = asn1Reader.readOID();
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    kdf_type_t kdfType = POLARSSL_KDF_NONE;
    POLARSSL_ERROR_HANDLER(
        ::oid_get_kdf_alg(&oidAsn1Buf, &kdfType)
    );

    // Read hash algorithm identifier
    asn1Reader.readSequence();
    oid = asn1Reader.readOID();
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    md_type_t mdType = POLARSSL_MD_NONE;
    POLARSSL_ERROR_HANDLER(
        ::oid_get_md_alg(&oidAsn1Buf, &mdType)
    );

    asn1Reader.readNull();
    *this = VirgilKDF(kdfType, mdType);
}
