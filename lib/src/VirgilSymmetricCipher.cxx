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

#include <virgil/crypto/VirgilSymmetricCipher.h>
using virgil::crypto::VirgilSymmetricCipher;
using virgil::crypto::VirgilSymmetricCipherImpl;

#include <polarssl/cipher.h>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/PolarsslException.h>

namespace virgil { namespace crypto {

class VirgilSymmetricCipherImpl {
public:
    VirgilSymmetricCipherImpl(cipher_type_t cipherType) : type(POLARSSL_CIPHER_NONE), ctx(0) {
        init_(cipherType);
    }

    VirgilSymmetricCipherImpl(const VirgilSymmetricCipherImpl& other) : type(POLARSSL_CIPHER_NONE), ctx(0) {
        init_(other.type);
    }

    VirgilSymmetricCipherImpl& operator=(const VirgilSymmetricCipherImpl& rhs) {
        if (this == &rhs) {
            return *this;
        }
        free_();
        init_(rhs.type);
        return *this;
    }

private:
    void init_(cipher_type_t cipherType) {
        type = cipherType;
        const cipher_info_t * info = cipher_info_from_type(cipherType);
        ctx = new cipher_context_t();
        ::cipher_init(ctx);
        POLARSSL_ERROR_HANDLER_DISPOSE(
            ::cipher_init_ctx(ctx, info),
            free_()
        );
    }

    void free_() throw() {
        type = POLARSSL_CIPHER_NONE;
        if (ctx) {
            ::cipher_free(ctx);
            delete ctx;
            ctx = 0;
        }
    }

public:
    cipher_type_t type;
    cipher_context_t *ctx;
};

}}

VirgilSymmetricCipher::VirgilSymmetricCipher(int type)
        : impl_(new VirgilSymmetricCipherImpl(static_cast<cipher_type_t>(type))) {
}

VirgilSymmetricCipher::VirgilSymmetricCipher(const VirgilSymmetricCipher& other)
        : impl_(new VirgilSymmetricCipherImpl(other.impl_->type)) {
}

VirgilSymmetricCipher& VirgilSymmetricCipher::operator=(const VirgilSymmetricCipher& rhs) {
    if (this == &rhs) {
        return *this;
    }
    VirgilSymmetricCipherImpl *newImpl = new VirgilSymmetricCipherImpl(rhs.impl_->type);
    if (impl_) {
        delete impl_;
    }
    impl_ = newImpl;
    return *this;
}

VirgilSymmetricCipher::~VirgilSymmetricCipher() throw() {
}

VirgilSymmetricCipher VirgilSymmetricCipher::aes256() {
    return VirgilSymmetricCipher(POLARSSL_CIPHER_AES_256_CBC);
}

std::string VirgilSymmetricCipher::name() const {
    return ::cipher_get_name(impl_->ctx);
}

size_t VirgilSymmetricCipher::blockSize() const {
    return ::cipher_get_block_size(impl_->ctx);
}

size_t VirgilSymmetricCipher::ivSize() const {
    return ::cipher_get_iv_size(impl_->ctx);
}

size_t VirgilSymmetricCipher::keySize() const {
    return ::cipher_get_key_size(impl_->ctx);
}

size_t VirgilSymmetricCipher::keyLength() const {
    return size_t((keySize() + 7) / 8);
}

void VirgilSymmetricCipher::setEncryptionKey(const VirgilByteArray& key) {
    POLARSSL_ERROR_HANDLER(
        ::cipher_setkey(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key) * 8, POLARSSL_ENCRYPT)
    );
}

void VirgilSymmetricCipher::setDecryptionKey(const VirgilByteArray& key) {
    POLARSSL_ERROR_HANDLER(
        ::cipher_setkey(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key) * 8, POLARSSL_DECRYPT)
    );
}

void VirgilSymmetricCipher::setPadding(VirgilSymmetricCipherPadding padding) {
    cipher_padding_t paddingCode = POLARSSL_PADDING_NONE;
    switch (padding) {
        case VirgilSymmetricCipherPadding_PKCS7:
            paddingCode = POLARSSL_PADDING_PKCS7;
            break;
        case VirgilSymmetricCipherPadding_OneAndZeros:
            paddingCode = POLARSSL_PADDING_ONE_AND_ZEROS;
            break;
        case VirgilSymmetricCipherPadding_ZerosAndLen:
            paddingCode = POLARSSL_PADDING_ZEROS_AND_LEN;
            break;
        case VirgilSymmetricCipherPadding_Zeros:
            paddingCode = POLARSSL_PADDING_ZEROS;
            break;
    }
    POLARSSL_ERROR_HANDLER(::cipher_set_padding_mode(impl_->ctx, paddingCode));
}

void VirgilSymmetricCipher::setIV(const VirgilByteArray& iv) {
    POLARSSL_ERROR_HANDLER(
        ::cipher_set_iv(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(iv))
    );
}

void VirgilSymmetricCipher::reset() {
    POLARSSL_ERROR_HANDLER(::cipher_reset(impl_->ctx));
}

void VirgilSymmetricCipher::clear() {
    if (impl_) {
        VirgilSymmetricCipherImpl *newImpl = new VirgilSymmetricCipherImpl(impl_->type);
        delete impl_;
        impl_ = newImpl;
    }
}

VirgilByteArray VirgilSymmetricCipher::update(const VirgilByteArray& input) {
    size_t writtenBytes = 0;
    size_t bufLen = input.size() + this->blockSize();
    unsigned char * buf = new unsigned char[bufLen];
    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::cipher_update(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(input), buf, &writtenBytes),
        { // If error, dispose allocated memory.
            delete [] buf;
        }
    );
    VirgilByteArray result = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(buf, writtenBytes);
    delete [] buf;
    return result;
}

VirgilByteArray VirgilSymmetricCipher::finish() {
    size_t writtenBytes = 0;
    size_t bufLen = this->blockSize();
    unsigned char * buf = new unsigned char[bufLen];
    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::cipher_finish(impl_->ctx, buf, &writtenBytes),
        { // If error, dispose allocated memory.
            delete [] buf;
        }
    );
    VirgilByteArray result = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(buf, writtenBytes);
    delete [] buf;

    return result;
}
