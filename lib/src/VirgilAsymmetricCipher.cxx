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

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;
using virgil::crypto::VirgilAsymmetricCipherImpl;

#include <cstring>

#include <polarssl/pk.h>
#include <polarssl/md.h>
#include <polarssl/asn1.h>
#include <polarssl/base64.h>
#include <polarssl/rsa.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/VirgilKeyPairGenerator.h>
using virgil::crypto::VirgilKeyPairGenerator;

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/PolarsslException.h>

/// @name Private section
namespace virgil { namespace crypto {

class VirgilAsymmetricCipherImpl {
public:
    VirgilAsymmetricCipherImpl(pk_type_t pkType) : type(POLARSSL_PK_NONE), ctx(0) {
        init_(pkType);
    }

    VirgilAsymmetricCipherImpl(const VirgilAsymmetricCipherImpl& other): type(POLARSSL_PK_NONE), ctx(0) {
        init_(other.type);
    }

    VirgilAsymmetricCipherImpl& operator=(const VirgilAsymmetricCipherImpl& rhs) {
        if (this == &rhs) {
            return *this;
        }
        free_();
        init_(rhs.type);
        return *this;
    }

private:
    void init_(pk_type_t pkType) {
        type = pkType;
        ctx = new pk_context();
        ::pk_init(ctx);
        if (type != POLARSSL_PK_NONE) {
            const pk_info_t * info = pk_info_from_type(type);
            POLARSSL_ERROR_HANDLER_DISPOSE(
                ::pk_init_ctx(ctx, info),
                free_()
            );
        }
    }

    void free_() {
        type = POLARSSL_PK_NONE;
        if (ctx) {
            ::pk_free(ctx);
            delete ctx;
            ctx = 0;
        }
    }

public:
    pk_type_t type;
    pk_context * ctx;
};

}}

VirgilAsymmetricCipher::VirgilAsymmetricCipher(int type)
        : impl_(new VirgilAsymmetricCipherImpl(static_cast<pk_type_t>(type))) {
}

VirgilAsymmetricCipher::VirgilAsymmetricCipher(const VirgilAsymmetricCipher& other)
        : impl_(new VirgilAsymmetricCipherImpl(other.impl_->type)) {
}

VirgilAsymmetricCipher& VirgilAsymmetricCipher::operator=(const VirgilAsymmetricCipher& rhs) {
    if (this == &rhs) {
        return *this;
    }
    VirgilAsymmetricCipherImpl *newImpl = new VirgilAsymmetricCipherImpl(rhs.impl_->type);
    if (impl_) {
        delete impl_;
    }
    impl_ = newImpl;
    return *this;
}

VirgilAsymmetricCipher::~VirgilAsymmetricCipher() throw() {
    if (impl_) {
        delete impl_;
        impl_ = 0;
    }
}

/**
 * Convert public / private key helper.
 */

class PolarsslKeyExport {
public:
    typedef enum {
        DER = 0,
        PEM
    } Format;
    typedef enum {
        Public = 0,
        Private
    } Type;
    PolarsslKeyExport(pk_context *ctx, Format format, Type type, const VirgilByteArray& pwd = VirgilByteArray())
            : ctx_(ctx), format_(format), type_(type), pwd_(pwd)  {}

    Format format() const { return format_; }
    Type type() const { return type_; }

    int operator()(unsigned char *buf, size_t bufLen) {
        if (type_ == Public && format_ == PEM) {
            return ::pk_write_pubkey_pem(ctx_, buf, bufLen);
        }
        if (type_ == Public && format_ == DER) {
            return ::pk_write_pubkey_der(ctx_, buf, bufLen);
        }
        if (type_ == Private && format_ == PEM) {
            if (pwd_.empty()) {
                return ::pk_write_key_pem(ctx_, buf, bufLen);
            } else {
                return ::pk_write_key_enc_pem(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_));
            }
        }
        if (type_ == Private && format_ == DER) {
            if (pwd_.empty()) {
                return ::pk_write_key_der(ctx_, buf, bufLen);
            } else {
                return ::pk_write_key_enc_der(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_));
            }
        }
        throw std::logic_error("Unexpected PolarsslKeyExport::Format and/or PolarsslKeyExport::Type value was given.");
    }
private:
    pk_context *ctx_;
    Format format_;
    Type type_;
    VirgilByteArray pwd_;
};

static VirgilByteArray exportKey_(PolarsslKeyExport& polarsslKeyExport) {
    size_t bufLen = 2048;
    unsigned char *buf = 0;
    int result = 0;
    do {
        buf = new unsigned char[bufLen];
        result = polarsslKeyExport(buf, bufLen);
        if (result < 0) {
            delete [] buf;
            buf = 0;
        }
    } while (result == POLARSSL_ERR_ASN1_BUF_TOO_SMALL || result == POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL);

    POLARSSL_ERROR_HANDLER(result); // No memory leak, if it is an error 'buf' variable will be deallocated earlier.

    unsigned char * writtenBytesBegin = buf;
    size_t writtenBytes = 0;
    if (polarsslKeyExport.format() == PolarsslKeyExport::DER && result > 0) {
        // Define written bytes for DER format
        writtenBytes = result;
        // Change result's begin for DER format.
        writtenBytesBegin = buf + bufLen - writtenBytes;
    } else if (polarsslKeyExport.format() == PolarsslKeyExport::PEM && result == 0) {
        // Define written bytes for PEM format
        writtenBytes = ::strlen(reinterpret_cast<const char *>(buf));
    }

    VirgilByteArray out = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(writtenBytesBegin, writtenBytes);

    if (buf) {
        delete [] buf;
        buf = 0;
    }

    return out;
}

template <class EncDecFunc>
VirgilByteArray processEncryptionDecryption_(EncDecFunc processFunc, pk_context *ctx, const VirgilByteArray& in) {
    const char *pers = "encrypt_decrypt";

    const size_t bufLenMax = 1024;
    unsigned char buf[bufLenMax];
    size_t bufLen = 0;

    entropy_context entropy;
    entropy_init(&entropy);

    ctr_drbg_context ctr_drbg;
    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)),
        ::entropy_free(&entropy)
    );

    POLARSSL_ERROR_HANDLER_DISPOSE(
        processFunc(ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(in), (unsigned char *)buf, &bufLen, bufLenMax,
                ctr_drbg_random, &ctr_drbg),
        {
            ::ctr_drbg_free(&ctr_drbg);
            ::entropy_free(&entropy);
        }
    );
    ::ctr_drbg_free(&ctr_drbg);
    ::entropy_free(&entropy);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(buf, bufLen);
}

/// @name Public section

VirgilAsymmetricCipher VirgilAsymmetricCipher::none() {
    return VirgilAsymmetricCipher(POLARSSL_PK_NONE);
}

VirgilAsymmetricCipher VirgilAsymmetricCipher::rsa() {
    return VirgilAsymmetricCipher(POLARSSL_PK_RSA);
}

VirgilAsymmetricCipher VirgilAsymmetricCipher::ec() {
    return VirgilAsymmetricCipher(POLARSSL_PK_ECKEY);
}

size_t VirgilAsymmetricCipher::keySize() const {
    return ::pk_get_size(impl_->ctx);
}

size_t VirgilAsymmetricCipher::keyLength() const {
    return ::pk_get_len(impl_->ctx);
}

void VirgilAsymmetricCipher::setPrivateKey(const VirgilByteArray& key, const VirgilByteArray& pwd) {
    POLARSSL_ERROR_HANDLER(
        ::pk_parse_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd));
    );
}

void VirgilAsymmetricCipher::setPublicKey(const VirgilByteArray& key) {
    POLARSSL_ERROR_HANDLER(
        ::pk_parse_public_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key));
    );
}

void VirgilAsymmetricCipher::genKeyPair(const VirgilKeyPairGenerator& keyPairGenerator) {
    keyPairGenerator.generate(impl_->ctx);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToDER(const VirgilByteArray& pwd) const {
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::DER, PolarsslKeyExport::Private, pwd);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToDER() const {
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::DER, PolarsslKeyExport::Public);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToPEM(const VirgilByteArray& pwd) const {
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::PEM, PolarsslKeyExport::Private, pwd);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToPEM() const {
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::PEM, PolarsslKeyExport::Public);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::encrypt(const VirgilByteArray& in) const {
    return processEncryptionDecryption_(::pk_encrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::decrypt(const VirgilByteArray& in) const {
    return processEncryptionDecryption_(::pk_decrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::sign(const VirgilByteArray& hash) const {
    const char *pers = "sign";

    unsigned char sign[POLARSSL_MPI_MAX_SIZE];
    size_t actualSignLen = 0;

    entropy_context entropy;
    entropy_init(&entropy);

    ctr_drbg_context ctr_drbg;
    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)),
        ::entropy_free(&entropy)
    );

    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::pk_sign(impl_->ctx, POLARSSL_MD_NONE, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(hash), sign, &actualSignLen,
                ctr_drbg_random, &ctr_drbg),
        {
            ::ctr_drbg_free(&ctr_drbg);
            ::entropy_free(&entropy);
        }
    );

    ::ctr_drbg_free(&ctr_drbg);
    ::entropy_free(&entropy);

    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(sign, actualSignLen);
}

bool VirgilAsymmetricCipher::verify(const VirgilByteArray& hash, const VirgilByteArray& sign) const {
    return ::pk_verify(impl_->ctx, POLARSSL_MD_NONE,
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(hash), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(sign)) == 0;
}

