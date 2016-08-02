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

#define MODULE_NAME "VirgilHash"

#include <virgil/crypto/foundation/VirgilHash.h>

#include <mbedtls/md.h>
#include <mbedtls/oid.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/internal/utils.h>
#include <virgil/crypto/foundation/internal/mbedtls_context.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCryptoException;

using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

namespace virgil { namespace crypto { namespace foundation {

class ImplInfo {
public:
    explicit ImplInfo(const mbedtls_md_context_t* md_ctx) : md_ctx_(md_ctx) {
        if (md_ctx_ == nullptr) {
            throw make_error(VirgilCryptoError::InvalidState);
        }
    }

    mbedtls_md_type_t type() const noexcept {
        return mbedtls_md_get_type(md_ctx_->md_info);
    }

    const char* name() const noexcept {
        return mbedtls_md_get_name(md_ctx_->md_info);
    }

    size_t size() const noexcept {
        return mbedtls_md_get_size(md_ctx_->md_info);
    }

private:
    const mbedtls_md_context_t* md_ctx_;
};

struct VirgilHash::Impl {
    Impl() : md_ctx(), hmac_ctx(), info(md_ctx.get()) {}

    template<typename TypeOrName>
    void setup(TypeOrName typeOrName) {
        md_ctx.setup(typeOrName, 0);
        hmac_ctx.setup(typeOrName, 1);
    }

    internal::mbedtls_context<mbedtls_md_context_t> md_ctx;
    internal::mbedtls_context<mbedtls_md_context_t> hmac_ctx;
    const ImplInfo info;
};

}}}

namespace virgil { namespace crypto { namespace foundation {

template<>
VirgilHash::VirgilHash(mbedtls_md_type_t type) : impl_(new Impl()) {
    impl_->setup(type);
}

template<>
VirgilHash::VirgilHash(const char* name) : impl_(new Impl()) {
    impl_->setup(name);
}

}}}

VirgilHash::VirgilHash() : impl_(new Impl()) {
}

VirgilHash::~VirgilHash() noexcept {}

VirgilHash::VirgilHash(VirgilHash&& other) = default;

VirgilHash& VirgilHash::operator=(VirgilHash&& rhs) = default;


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
    return VirgilHash(VirgilByteArrayUtils::bytesToString(name).c_str());
}

std::string VirgilHash::name() const {
    checkState();
    return std::string(impl_->info.name());
}

int VirgilHash::type() const {
    return static_cast<int>(impl_->info.type());
}

void VirgilHash::start() {
    checkState();
    system_crypto_handler(
            mbedtls_md_starts(impl_->md_ctx.get()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
}

void VirgilHash::update(const VirgilByteArray& data) {
    checkState();
    system_crypto_handler(
            mbedtls_md_update(impl_->md_ctx.get(), data.data(), data.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
}

VirgilByteArray VirgilHash::finish() {
    checkState();
    VirgilByteArray digest(impl_->info.size());
    system_crypto_handler(
            mbedtls_md_finish(impl_->md_ctx.get(), digest.data()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
    return digest;
}

VirgilByteArray VirgilHash::hash(const VirgilByteArray& data) const {
    checkState();
    VirgilByteArray digest(impl_->info.size());
    system_crypto_handler(
            mbedtls_md(impl_->md_ctx.get()->md_info, data.data(), data.size(), digest.data()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
    return digest;
}

void VirgilHash::hmacStart(const VirgilByteArray& key) {
    checkState();
    system_crypto_handler(
            mbedtls_md_hmac_starts(impl_->hmac_ctx.get(), key.data(), key.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
}

void VirgilHash::hmacReset() {
    checkState();
    system_crypto_handler(
            mbedtls_md_hmac_reset(impl_->hmac_ctx.get()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
}

void VirgilHash::hmacUpdate(const VirgilByteArray& data) {
    checkState();
    system_crypto_handler(
            mbedtls_md_hmac_update(impl_->hmac_ctx.get(), data.data(), data.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
}

VirgilByteArray VirgilHash::hmacFinish() {
    checkState();
    VirgilByteArray digest(impl_->info.size());
    system_crypto_handler(
            mbedtls_md_hmac_finish(impl_->hmac_ctx.get(), digest.data()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
    return digest;
}

VirgilByteArray VirgilHash::hmac(const VirgilByteArray& key, const VirgilByteArray& data) const {
    checkState();
    VirgilByteArray digest(impl_->info.size());
    system_crypto_handler(
            mbedtls_md_hmac(impl_->hmac_ctx.get()->md_info, key.data(), key.size(),
                    data.data(), data.size(), digest.data()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
    return digest;
}

void VirgilHash::checkState() const {
    if (impl_->info.type() == MBEDTLS_MD_NONE) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
}

size_t VirgilHash::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    const char* oid = 0;
    size_t oidLen;
    system_crypto_handler(
            mbedtls_oid_get_oid_by_md(impl_->info.type(), &oid, &oidLen),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );
    size_t len = 0;
    len += asn1Writer.writeNull();
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);
    return len + childWrittenBytes;
}

void VirgilHash::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();
    VirgilByteArray oid = VirgilByteArrayUtils::stringToBytes(asn1Reader.readOID());

    mbedtls_asn1_buf oidAsn1Buf;
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = oid.data();

    mbedtls_md_type_t type = MBEDTLS_MD_NONE;
    system_crypto_handler(
            mbedtls_oid_get_md_alg(&oidAsn1Buf, &type),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );

    asn1Reader.readNull();
    *this = VirgilHash(type);
}
