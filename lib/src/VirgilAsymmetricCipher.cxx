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

#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::VirgilAsymmetricCipherImpl;

#include <cstring>

#include <polarssl/pk.h>
#include <polarssl/md.h>
#include <polarssl/oid.h>
#include <polarssl/asn1.h>
#include <polarssl/base64.h>
#include <polarssl/rsa.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include <virgil/crypto/VirgilByteArray.h>
using virgil::crypto::VirgilByteArray;

#include <virgil/crypto/foundation/VirgilKeyPairGenerator.h>
using virgil::crypto::foundation::VirgilKeyPairGenerator;

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;

#include <virgil/crypto/foundation/PolarsslException.h>
using virgil::crypto::foundation::PolarsslException;

/// @name Private section
namespace virgil { namespace crypto { namespace foundation {

class VirgilAsymmetricCipherImpl {
public:
    VirgilAsymmetricCipherImpl(pk_type_t pkType) : ctx(0) {
        init_(pkType);
    }

    VirgilAsymmetricCipherImpl(const VirgilAsymmetricCipherImpl& other): ctx(0) {
        init_(other.pkType());
    }

    ~VirgilAsymmetricCipherImpl() {
        free_();
    }

    VirgilAsymmetricCipherImpl& operator=(const VirgilAsymmetricCipherImpl& rhs) {
        if (this == &rhs) {
            return *this;
        }
        free_();
        init_(rhs.pkType());
        return *this;
    }

    pk_type_t pkType() const {
        if (ctx != 0) {
            return ::pk_get_type(ctx);
        } else {
            return POLARSSL_PK_NONE;
        }
    }
private:
    void init_(pk_type_t pkType) {
        ctx = new pk_context();
        ::pk_init(ctx);
        if (pkType != POLARSSL_PK_NONE) {
            const pk_info_t * info = pk_info_from_type(pkType);
            POLARSSL_ERROR_HANDLER_DISPOSE(
                ::pk_init_ctx(ctx, info),
                free_()
            );
        }
    }

    void free_() {
        if (ctx) {
            ::pk_free(ctx);
            delete ctx;
            ctx = 0;
        }
    }

public:
    pk_context * ctx;
};

}}}

VirgilAsymmetricCipher::VirgilAsymmetricCipher(int type)
        : impl_(new VirgilAsymmetricCipherImpl(static_cast<pk_type_t>(type))) {
}

VirgilAsymmetricCipher::VirgilAsymmetricCipher(const VirgilAsymmetricCipher& other)
        : impl_(new VirgilAsymmetricCipherImpl(other.impl_->pkType())) {
}

VirgilAsymmetricCipher& VirgilAsymmetricCipher::operator=(const VirgilAsymmetricCipher& rhs) {
    if (this == &rhs) {
        return *this;
    }
    VirgilAsymmetricCipherImpl *newImpl = new VirgilAsymmetricCipherImpl(rhs.impl_->pkType());
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
                return ::pk_write_key_pem_ext(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_));
            }
        }
        if (type_ == Private && format_ == DER) {
            if (pwd_.empty()) {
                return ::pk_write_key_der(ctx_, buf, bufLen);
            } else {
                return ::pk_write_key_der_ext(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_));
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
    VirgilByteArray exportedKey(2048);
    int result = 0;
    bool isNotEnoughSpace = false;
    do {
        result = polarsslKeyExport(exportedKey.data(), exportedKey.size());
        isNotEnoughSpace = (result == POLARSSL_ERR_ASN1_BUF_TOO_SMALL) ||
                           (result == POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL);
        if (isNotEnoughSpace) {
            exportedKey.resize(2 * exportedKey.size());
        }
    } while (isNotEnoughSpace);

    POLARSSL_ERROR_HANDLER(result);

    size_t writtenBytes = 0;
    if (polarsslKeyExport.format() == PolarsslKeyExport::DER && result > 0) {
        // Define written bytes for DER format
        writtenBytes = result;
        // Change result's begin for DER format.
        memmove(exportedKey.data(), exportedKey.data() + exportedKey.size() - writtenBytes, writtenBytes);
    } else if (polarsslKeyExport.format() == PolarsslKeyExport::PEM && result == 0) {
        // Define written bytes for PEM format
        writtenBytes = ::strlen(reinterpret_cast<const char *>(exportedKey.data()));
    }

    exportedKey.resize(writtenBytes);
    return exportedKey;
}

template <class EncDecFunc>
VirgilByteArray processEncryptionDecryption_(EncDecFunc processFunc, pk_context *ctx, const VirgilByteArray& in) {
    const char *pers = "encrypt_decrypt";

    VirgilByteArray result(1024);
    size_t resultLen = 0;

    entropy_context entropy;
    entropy_init(&entropy);

    ctr_drbg_context ctr_drbg;
    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)),
        ::entropy_free(&entropy)
    );

    POLARSSL_ERROR_HANDLER_DISPOSE(
        processFunc(ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(in),
                (unsigned char *)result.data(), &resultLen, result.size(), ctr_drbg_random, &ctr_drbg),
        {
            ::ctr_drbg_free(&ctr_drbg);
            ::entropy_free(&entropy);
        }
    );
    ::ctr_drbg_free(&ctr_drbg);
    ::entropy_free(&entropy);
    result.resize(resultLen);
    return result;
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
    checkState();
    return ::pk_get_size(impl_->ctx);
}

size_t VirgilAsymmetricCipher::keyLength() const {
    checkState();
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
    checkState();
    keyPairGenerator.generate(impl_->ctx);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToDER(const VirgilByteArray& pwd) const {
    checkState();
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::DER, PolarsslKeyExport::Private, pwd);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToDER() const {
    checkState();
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::DER, PolarsslKeyExport::Public);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToPEM(const VirgilByteArray& pwd) const {
    checkState();
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::PEM, PolarsslKeyExport::Private, pwd);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToPEM() const {
    checkState();
    PolarsslKeyExport polarsslKeyExport(impl_->ctx, PolarsslKeyExport::PEM, PolarsslKeyExport::Public);
    return exportKey_(polarsslKeyExport);
}

VirgilByteArray VirgilAsymmetricCipher::encrypt(const VirgilByteArray& in) const {
    checkState();
    return processEncryptionDecryption_(::pk_encrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::decrypt(const VirgilByteArray& in) const {
    checkState();
    return processEncryptionDecryption_(::pk_decrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::sign(const VirgilByteArray& hash) const {
    checkState();
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
    checkState();
    return ::pk_verify(impl_->ctx, POLARSSL_MD_NONE,
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(hash), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(sign)) == 0;
}

size_t VirgilAsymmetricCipher::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    const char *oid = 0;
    size_t oidLen;
    size_t len = 0;
    if (impl_->pkType() == POLARSSL_PK_ECKEY && pk_ec(*impl_->ctx)->grp.id != POLARSSL_ECP_DP_NONE) {
        POLARSSL_ERROR_HANDLER(
            ::oid_get_oid_by_ec_grp(pk_ec(*impl_->ctx)->grp.id, &oid, &oidLen)
        );
        len += asn1Writer.writeOID(std::string(oid, oidLen));
    } else {
        len += asn1Writer.writeNull();
    }
    POLARSSL_ERROR_HANDLER(
        ::oid_get_oid_by_pk_alg(impl_->pkType(), &oid, &oidLen)
    );
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);
    return len + childWrittenBytes;
}

void VirgilAsymmetricCipher::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();
    std::string oid = asn1Reader.readOID();
    (void)asn1Reader.readData(); // Ignore params

    asn1_buf oidAsn1Buf;
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    pk_type_t type = POLARSSL_PK_NONE;
    POLARSSL_ERROR_HANDLER(
        ::oid_get_pk_alg(&oidAsn1Buf, &type)
    );

    *this = VirgilAsymmetricCipher(type);
}

void VirgilAsymmetricCipher::checkState() const {
    if (impl_->pkType() == POLARSSL_PK_NONE) {
        throw VirgilCryptoException(std::string("VirgilAsymmetricCipher: object has undefined algorithm.") +
                std::string(" Use one of the factory methods or method 'fromAsn1' to define PK algorithm."));
    }
}

