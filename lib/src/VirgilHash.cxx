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

#include <virgil/crypto/foundation/VirgilHash.h>

#include <string>

#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/PolarsslException.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Compatible.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::bytes2str;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;

using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::VirgilHashImpl;
using virgil::crypto::foundation::PolarsslException;
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

namespace virgil { namespace crypto { namespace foundation {

class VirgilHashImpl {
public:
    VirgilHashImpl(mbedtls_md_type_t mdType)
            : type(MBEDTLS_MD_NONE), info(0), digest(0), digestSize(0), ctx(0), hmacCtx(0) {
        init_(mdType);
    }

    VirgilHashImpl(const char * mdName)
            : type(MBEDTLS_MD_NONE), info(0), digest(0), digestSize(0), ctx(0), hmacCtx(0) {
        const mbedtls_md_info_t * mdInfo = mbedtls_md_info_from_string(mdName);
        mbedtls_md_type_t mdType = mdInfo ? mbedtls_md_get_type(mdInfo) : MBEDTLS_MD_NONE;
        init_(mdType);
    }

    ~VirgilHashImpl() throw() {
        free_();
    }

    VirgilHashImpl(const VirgilHashImpl& other)
            : type(MBEDTLS_MD_NONE), info(0), digest(0), digestSize(0), ctx(0), hmacCtx(0) {
        init_(other.type);
    }

    VirgilHashImpl& operator=(const VirgilHashImpl& rhs) {
        if (this == &rhs) {
            return *this;
        }
        free_();
        init_(rhs.type);
        return *this;
    }

private:
    void init_(mbedtls_md_type_t mdType) {
        type = mdType;
        if (mdType == MBEDTLS_MD_NONE) {
            return;
        }
        info = mbedtls_md_info_from_type(mdType);
        digestSize = mbedtls_md_get_size(info);
        digest = new unsigned char[digestSize];
        ctx = new mbedtls_md_context_t();
        MBEDTLS_ERROR_HANDLER_DISPOSE(
            ::mbedtls_md_setup(ctx, info, 0),
            free_()
        );
        hmacCtx = new mbedtls_md_context_t();
        MBEDTLS_ERROR_HANDLER_DISPOSE(
            ::mbedtls_md_setup(hmacCtx, info, 1),
            free_()
        );
    }

    void free_() throw() {
        if (digest) {
            delete [] digest;
            digest = 0;
            digestSize = 0;
        }
        if (ctx) {
            ::mbedtls_md_free(ctx);
            delete ctx;
            ctx = 0;
        }
        if (hmacCtx) {
            ::mbedtls_md_free(hmacCtx);
            delete hmacCtx;
            hmacCtx = 0;
        }
        type = MBEDTLS_MD_NONE;
        info = 0;
    }
public:
    mbedtls_md_type_t type; // hash algorithm type
    const mbedtls_md_info_t *info; // hash algorithm info
    unsigned char *digest; // pointer to the array that handles hash digest
    size_t digestSize; // size of hash digest
    mbedtls_md_context_t *ctx; // pointer to the hash context, is used for chaining hash
    mbedtls_md_context_t *hmacCtx; // pointer to the hmac hash context, is used for chaining hash
};

}}}

VirgilHash VirgilHash::md5() {
    return VirgilHash(MBEDTLS_MD_MD5);
}

VirgilHash VirgilHash::sha256() {
    return VirgilHash(MBEDTLS_MD_SHA256);
}

VirgilHash VirgilHash::sha384() {
    return VirgilHash(MBEDTLS_MD_SHA384);
}

VirgilHash VirgilHash::sha512() {
    return VirgilHash(MBEDTLS_MD_SHA512);
}

VirgilHash VirgilHash::withName(const VirgilByteArray& name) {
    return VirgilHash(bytes2str(name).c_str());
}

VirgilHash::VirgilHash() : impl_(new VirgilHashImpl(MBEDTLS_MD_NONE)) {
}

VirgilHash::VirgilHash(int type) : impl_(new VirgilHashImpl(static_cast<mbedtls_md_type_t>(type))) {
}

VirgilHash::VirgilHash(const char * name) : impl_(new VirgilHashImpl(name)) {
}

VirgilHash::~VirgilHash() throw() {
    if (impl_) {
        delete impl_;
        impl_ = 0;
    }
}

VirgilHash::VirgilHash(const VirgilHash& other) : impl_(new VirgilHashImpl(other.impl_->type)) {
}

VirgilHash& VirgilHash::operator=(const VirgilHash& rhs) {
    if (this == &rhs) {
        return *this;
    }
    VirgilHashImpl *newImpl = new VirgilHashImpl(rhs.impl_->type);
    if (impl_) {
        delete impl_;
    }
    impl_ = newImpl;
    return *this;
}

std::string VirgilHash::name() const {
    checkState();
    return std::string(::mbedtls_md_get_name(impl_->info));
}

int VirgilHash::type() const {
    return static_cast<int>(impl_->type);
}

void VirgilHash::start() {
    checkState();
    MBEDTLS_ERROR_HANDLER(::mbedtls_md_starts(impl_->ctx));
}

void VirgilHash::update(const VirgilByteArray& bytes) {
    checkState();
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_md_update(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(bytes));
    );
}

VirgilByteArray VirgilHash::finish() {
    checkState();
    MBEDTLS_ERROR_HANDLER(::mbedtls_md_finish(impl_->ctx, impl_->digest));
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(impl_->digest, impl_->digestSize);
}

VirgilByteArray VirgilHash::hash(const VirgilByteArray& bytes) const {
    checkState();
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_md(impl_->info, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(bytes), impl_->digest)
    );
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(impl_->digest, impl_->digestSize);
}

void VirgilHash::hmacStart(const VirgilByteArray& key) {
    checkState();
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_md_hmac_starts(impl_->hmacCtx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key));
    );
}

void VirgilHash::hmacReset() {
    checkState();
    MBEDTLS_ERROR_HANDLER(::mbedtls_md_hmac_reset(impl_->hmacCtx));
}

void VirgilHash::hmacUpdate(const VirgilByteArray& bytes) {
    checkState();
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_md_hmac_update(impl_->hmacCtx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(bytes));
    );
}

VirgilByteArray VirgilHash::hmacFinish() {
    checkState();
    MBEDTLS_ERROR_HANDLER(::mbedtls_md_hmac_finish(impl_->hmacCtx, impl_->digest));
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(impl_->digest, impl_->digestSize);
}

VirgilByteArray VirgilHash::hmac(const VirgilByteArray& key, const VirgilByteArray& bytes) const {
    checkState();
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_md_hmac(impl_->info, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key),
                VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(bytes), impl_->digest);
    );
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(impl_->digest, impl_->digestSize);
}

void VirgilHash::checkState() const {
    if (impl_->type == MBEDTLS_MD_NONE || impl_->info == 0 || impl_->ctx == 0) {
        throw VirgilCryptoException(std::string("VirgilHash: object has undefined algorithm.") +
                std::string(" Use one of the factory methods or method 'fromAsn1' to define hash algorithm."));
    }
}

size_t VirgilHash::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    const char *oid = 0;
    size_t oidLen;
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_oid_by_md(impl_->type, &oid, &oidLen)
    );
    size_t len = 0;
    len += asn1Writer.writeNull();
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);
    return len + childWrittenBytes;
}

void VirgilHash::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();
    std::string oid = asn1Reader.readOID();

    mbedtls_asn1_buf oidAsn1Buf;
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    mbedtls_md_type_t type = MBEDTLS_MD_NONE;
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_md_alg(&oidAsn1Buf, &type)
    );

    asn1Reader.readNull();
    *this = VirgilHash(type);
}


