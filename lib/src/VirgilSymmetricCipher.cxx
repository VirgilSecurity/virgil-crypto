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

#define MODULE_NAME "VirgilSymmetricCipher"

#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>

#include <mbedtls/cipher.h>
#include <mbedtls/oid.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/internal/utils.h>
#include <virgil/crypto/foundation/internal/mbedtls_context.h>
#include <virgil/crypto/foundation/internal/VirgilTagFilter.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;

using virgil::crypto::foundation::VirgilSymmetricCipher;
using virgil::crypto::foundation::VirgilSymmetricCipherImpl;
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;
using virgil::crypto::foundation::internal::VirgilTagFilter;


struct VirgilSymmetricCipher::Impl {
    internal::mbedtls_context <mbedtls_cipher_context_t> cipher_ctx;
    VirgilByteArray iv;
    VirgilByteArray authData;
    VirgilTagFilter tagFilter;
};

VirgilSymmetricCipher::VirgilSymmetricCipher() : impl_(std::make_unique<Impl>()) {}

VirgilSymmetricCipher::VirgilSymmetricCipher(VirgilSymmetricCipher&&) = default;

VirgilSymmetricCipher& VirgilSymmetricCipher::operator=(VirgilSymmetricCipher&&) = default;

VirgilSymmetricCipher::~VirgilSymmetricCipher() noexcept {}

VirgilSymmetricCipher VirgilSymmetricCipher::aes256() {
    VirgilSymmetricCipher cipher;
    cipher.impl_->cipher_ctx.setup(MBEDTLS_CIPHER_AES_256_GCM);
    return cipher;
}

std::string VirgilSymmetricCipher::name() const {
    checkState();
    return mbedtls_cipher_get_name(impl_->cipher_ctx.get());
}

size_t VirgilSymmetricCipher::blockSize() const {
    checkState();
    return mbedtls_cipher_get_block_size(impl_->cipher_ctx.get());
}

size_t VirgilSymmetricCipher::ivSize() const {
    checkState();
    return (size_t) mbedtls_cipher_get_iv_size(impl_->cipher_ctx.get());
}

size_t VirgilSymmetricCipher::keySize() const {
    checkState();
    return (size_t) mbedtls_cipher_get_key_bitlen(impl_->cipher_ctx.get());
}

size_t VirgilSymmetricCipher::keyLength() const {
    return size_t((keySize() + 7) / 8);
}

size_t VirgilSymmetricCipher::authTagLength() const {
    checkState();
    switch (mbedtls_cipher_get_cipher_mode(impl_->cipher_ctx.get())) {
        case MBEDTLS_MODE_GCM:
            return 16;
        default:
            return 0;
    }
}

bool VirgilSymmetricCipher::isEncryptionMode() const {
    checkState();
    return mbedtls_cipher_get_operation(impl_->cipher_ctx.get()) == MBEDTLS_ENCRYPT;
}

bool VirgilSymmetricCipher::isDecryptionMode() const {
    checkState();
    return mbedtls_cipher_get_operation(impl_->cipher_ctx.get()) == MBEDTLS_DECRYPT;
}

bool VirgilSymmetricCipher::isAuthMode() const {
    checkState();
    return mbedtls_cipher_get_cipher_mode(impl_->cipher_ctx.get()) == MBEDTLS_MODE_GCM;
}

bool VirgilSymmetricCipher::isSupportPadding() const {
    checkState();
    return mbedtls_cipher_get_cipher_mode(impl_->cipher_ctx.get()) == MBEDTLS_MODE_CBC;
}

void VirgilSymmetricCipher::setEncryptionKey(const VirgilByteArray& key) {
    checkState();
    system_crypto_handler(
            mbedtls_cipher_setkey(impl_->cipher_ctx.get(), key.data(), key.size() * 8, MBEDTLS_ENCRYPT),
            [](int) {
                std::throw_with_nested(
                        make_error(VirgilCryptoError::InvalidArgument, "Bad key for symmetric encryption."));
            }
    );
}

void VirgilSymmetricCipher::setDecryptionKey(const VirgilByteArray& key) {
    checkState();
    system_crypto_handler(
            mbedtls_cipher_setkey(impl_->cipher_ctx.get(), key.data(), key.size() * 8, MBEDTLS_DECRYPT),
            [](int) {
                std::throw_with_nested(
                        make_error(VirgilCryptoError::InvalidArgument, "Bad key for symmetric decryption."));
            }
    );
}

void VirgilSymmetricCipher::setPadding(VirgilSymmetricCipherPadding padding) {
    checkState();
    mbedtls_cipher_padding_t paddingCode = MBEDTLS_PADDING_NONE;
    switch (padding) {
        case VirgilSymmetricCipherPadding_PKCS7:
            paddingCode = MBEDTLS_PADDING_PKCS7;
            break;
        case VirgilSymmetricCipherPadding_OneAndZeros:
            paddingCode = MBEDTLS_PADDING_ONE_AND_ZEROS;
            break;
        case VirgilSymmetricCipherPadding_ZerosAndLen:
            paddingCode = MBEDTLS_PADDING_ZEROS_AND_LEN;
            break;
        case VirgilSymmetricCipherPadding_Zeros:
            paddingCode = MBEDTLS_PADDING_ZEROS;
            break;
    }
    system_crypto_handler(
            mbedtls_cipher_set_padding_mode(impl_->cipher_ctx.get(), paddingCode),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );
}

void VirgilSymmetricCipher::setIV(const VirgilByteArray& iv) {
    checkState();
    system_crypto_handler(
            mbedtls_cipher_set_iv(impl_->cipher_ctx.get(), iv.data(), iv.size()),
            [](int) {
                std::throw_with_nested(
                        make_error(VirgilCryptoError::InvalidArgument, "Bad input vector for symmetric cipher."));
            }
    );
    impl_->iv = iv;
}

void VirgilSymmetricCipher::setAuthData(const virgil::crypto::VirgilByteArray& authData) {
    checkState();
    impl_->authData = authData;
}

void VirgilSymmetricCipher::reset() {
    checkState();
    system_crypto_handler(
            mbedtls_cipher_reset(impl_->cipher_ctx.get()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
    if (mbedtls_cipher_get_cipher_mode(impl_->cipher_ctx.get()) == MBEDTLS_MODE_GCM) {
        system_crypto_handler(
                mbedtls_cipher_update_ad(impl_->cipher_ctx.get(), impl_->authData.data(), impl_->authData.size()),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }

        );
        if (isDecryptionMode()) {
            impl_->tagFilter.reset(blockSize());
        }
    }
}

void VirgilSymmetricCipher::clear() {
    auto cipher_type = mbedtls_cipher_get_type(impl_->cipher_ctx.get());
    impl_->cipher_ctx.clear();
    impl_->iv.clear();
    impl_->authData.clear();
    impl_->tagFilter.reset(0);
    // Restore algorithm type
    if (cipher_type != MBEDTLS_CIPHER_NONE) {
        impl_->cipher_ctx.setup(cipher_type);
    }
}

VirgilByteArray VirgilSymmetricCipher::crypt(const VirgilByteArray& input, const VirgilByteArray& iv) {
    checkState();
    setIV(iv);
    reset();
    VirgilByteArray firstChunk = update(input);
    VirgilByteArray lastChunk = finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), lastChunk.begin(), lastChunk.end());

    return result;
}

VirgilByteArray VirgilSymmetricCipher::update(const VirgilByteArray& input) {
    checkState();
    size_t writtenBytes = 0;
    size_t bufLen = input.size() + this->blockSize();
    VirgilByteArray result(bufLen);

    if (isDecryptionMode() && isAuthMode()) {
        impl_->tagFilter.process(input);
        if (impl_->tagFilter.hasData()) {
            VirgilByteArray data = impl_->tagFilter.popData();
            system_crypto_handler(
                    mbedtls_cipher_update(impl_->cipher_ctx.get(), data.data(), data.size(), result.data(),
                            &writtenBytes),
                    [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
            );
        }
    } else {
        system_crypto_handler(
                mbedtls_cipher_update(impl_->cipher_ctx.get(), input.data(), input.size(), result.data(),
                        &writtenBytes),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
        );
    }

    result.resize(writtenBytes);
    return result;
}

VirgilByteArray VirgilSymmetricCipher::finish() {
    checkState();
    size_t writtenBytes = 0;
    VirgilByteArray result(blockSize());
    system_crypto_handler(
            mbedtls_cipher_finish(impl_->cipher_ctx.get(), result.data(), &writtenBytes),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );
    result.resize(writtenBytes);
    if (isAuthMode()) {
        if (isEncryptionMode()) {
            VirgilByteArray tag(authTagLength());
            system_crypto_handler(
                    mbedtls_cipher_write_tag(impl_->cipher_ctx.get(), tag.data(), tag.size()),
                    [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
            );
            result.insert(result.end(), tag.begin(), tag.end());
        } else if (isDecryptionMode()) {
            VirgilByteArray tag = impl_->tagFilter.tag();
            system_crypto_handler(
                    mbedtls_cipher_check_tag(impl_->cipher_ctx.get(), tag.data(), tag.size()),
                    [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
            );
        }
    }
    return result;
}

void VirgilSymmetricCipher::checkState() const {
    if (impl_->cipher_ctx.get()->cipher_info == nullptr) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
}

size_t VirgilSymmetricCipher::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    const char* oid = 0;
    size_t oidLen;
    system_crypto_handler(
            mbedtls_oid_get_oid_by_cipher_alg(mbedtls_cipher_get_type(impl_->cipher_ctx.get()), &oid, &oidLen),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );
    size_t len = 0;
    len += asn1Writer.writeOctetString(impl_->iv);
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);
    return len + childWrittenBytes;
}

void VirgilSymmetricCipher::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();

    VirgilByteArray oid = VirgilByteArrayUtils::stringToBytes(asn1Reader.readOID());
    mbedtls_asn1_buf oidAsn1Buf;
    oidAsn1Buf.p = oid.data();
    oidAsn1Buf.len = oid.size();

    mbedtls_cipher_type_t type = MBEDTLS_CIPHER_NONE;
    system_crypto_handler(
            mbedtls_oid_get_cipher_alg(&oidAsn1Buf, &type),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );

    clear();
    impl_->cipher_ctx.setup(type);
    setIV(asn1Reader.readOctetString());
}
