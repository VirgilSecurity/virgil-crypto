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

#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

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
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/PolarsslException.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::VirgilKeyPair;

using virgil::crypto::foundation::PolarsslException;
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::VirgilAsymmetricCipherImpl;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;

/**
 * @brief Throw exception if password is too long.
 * @note MbedTLS PKCS#12 restriction.
 */
static void checkPasswordLen(size_t pwdLen) {
    const size_t kPasswordLengthMax = 31;
    if (pwdLen > kPasswordLengthMax) {
        std::ostringstream errMsg;
        errMsg << "Password is too long. Max length is " << kPasswordLengthMax << " bytes.";
        throw VirgilCryptoException(errMsg.str());
    }
}

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

VirgilAsymmetricCipher::VirgilAsymmetricCipher()
        : impl_(new VirgilAsymmetricCipherImpl(POLARSSL_PK_NONE)) {
}

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

size_t VirgilAsymmetricCipher::keySize() const {
    checkState();
    return ::pk_get_size(impl_->ctx);
}

size_t VirgilAsymmetricCipher::keyLength() const {
    checkState();
    return ::pk_get_len(impl_->ctx);
}

bool VirgilAsymmetricCipher::isKeyPairMatch(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    pk_context public_ctx;
    pk_init(&public_ctx);
    POLARSSL_ERROR_HANDLER(
        ::pk_parse_public_key(&public_ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(publicKey))
    );

    pk_context private_ctx;
    pk_init(&private_ctx);
    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::pk_parse_key(&private_ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(privateKey),
                VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(privateKeyPassword)),
        ::pk_free(&public_ctx);
    );

    int result = ::pk_check_pair(&public_ctx, &private_ctx);

    ::pk_free(&public_ctx);
    ::pk_free(&private_ctx);

    return  result == 0;
}

bool VirgilAsymmetricCipher::checkPrivateKeyPassword(const VirgilByteArray& key,
        const VirgilByteArray& pwd) {

    checkPasswordLen(pwd.size());
    pk_context private_ctx;
    pk_init(&private_ctx);
    int result = ::pk_parse_key(&private_ctx,
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd));
    ::pk_free(&private_ctx);
    return result == 0;
}

bool VirgilAsymmetricCipher::isPrivateKeyEncrypted(const VirgilByteArray& privateKey) {
    return !checkPrivateKeyPassword(privateKey, VirgilByteArray());
}

void VirgilAsymmetricCipher::setPrivateKey(const VirgilByteArray& key, const VirgilByteArray& pwd) {
    checkPasswordLen(pwd.size());
    POLARSSL_ERROR_HANDLER(
        ::pk_parse_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd));
    );
}

void VirgilAsymmetricCipher::setPublicKey(const VirgilByteArray& key) {
    POLARSSL_ERROR_HANDLER(
        ::pk_parse_public_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(key));
    );
}

void VirgilAsymmetricCipher::genKeyPair(VirgilKeyPair::Type type) {
    int rsaSize = 0;
    ecp_group_id ecTypeId = POLARSSL_ECP_DP_NONE;
    switch (type) {
        case VirgilKeyPair::Type_RSA_256:
            rsaSize = 256;
            break;
        case VirgilKeyPair::Type_RSA_512:
            rsaSize = 512;
            break;
        case VirgilKeyPair::Type_RSA_1024:
            rsaSize = 1024;
            break;
        case VirgilKeyPair::Type_RSA_2048:
            rsaSize = 2048;
            break;
        case VirgilKeyPair::Type_RSA_3072:
            rsaSize = 3072;
            break;
        case VirgilKeyPair::Type_RSA_4096:
            rsaSize = 4096;
            break;
        case VirgilKeyPair::Type_RSA_8192:
            rsaSize = 8192;
            break;
        case VirgilKeyPair::Type_EC_SECP192R1:
            ecTypeId = POLARSSL_ECP_DP_SECP192R1;
            break;
        case VirgilKeyPair::Type_EC_SECP224R1:
            ecTypeId = POLARSSL_ECP_DP_SECP224R1;
            break;
        case VirgilKeyPair::Type_EC_SECP256R1:
            ecTypeId = POLARSSL_ECP_DP_SECP256R1;
            break;
        case VirgilKeyPair::Type_EC_SECP384R1:
            ecTypeId = POLARSSL_ECP_DP_SECP384R1;
            break;
        case VirgilKeyPair::Type_EC_SECP521R1:
            ecTypeId = POLARSSL_ECP_DP_SECP521R1;
            break;
        case VirgilKeyPair::Type_EC_BP256R1:
            ecTypeId = POLARSSL_ECP_DP_BP256R1;
            break;
        case VirgilKeyPair::Type_EC_BP384R1:
            ecTypeId = POLARSSL_ECP_DP_BP384R1;
            break;
        case VirgilKeyPair::Type_EC_BP512R1:
            ecTypeId = POLARSSL_ECP_DP_BP512R1;
            break;
        case VirgilKeyPair::Type_EC_M221:
            ecTypeId = POLARSSL_ECP_DP_M221;
            break;
        case VirgilKeyPair::Type_EC_M255:
            ecTypeId = POLARSSL_ECP_DP_M255;
            break;
        case VirgilKeyPair::Type_EC_M383:
            ecTypeId = POLARSSL_ECP_DP_M383;
            break;
        case VirgilKeyPair::Type_EC_M511:
            ecTypeId = POLARSSL_ECP_DP_M511;
            break;
        case VirgilKeyPair::Type_EC_SECP192K1:
            ecTypeId = POLARSSL_ECP_DP_SECP192K1;
            break;
        case VirgilKeyPair::Type_EC_SECP224K1:
            ecTypeId = POLARSSL_ECP_DP_SECP224K1;
            break;
        case VirgilKeyPair::Type_EC_SECP256K1:
            ecTypeId = POLARSSL_ECP_DP_SECP256K1;
            break;
        case VirgilKeyPair::Type_Default:
        default:
            ecTypeId = POLARSSL_ECP_DP_BP512R1;
            break;
    }

    const char *pers = "virgil_gen_keypair";
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;

    ::entropy_init(&entropy);

    POLARSSL_ERROR_HANDLER(
        ::ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))
    );

    if (rsaSize > 0) {
        *this = VirgilAsymmetricCipher(POLARSSL_PK_RSA);
        POLARSSL_ERROR_HANDLER_DISPOSE(
            ::rsa_gen_key(pk_rsa(*(impl_->ctx)), ctr_drbg_random, &ctr_drbg, rsaSize, 65537),
            ::entropy_free(&entropy)
        );
    } else if (ecTypeId != POLARSSL_ECP_DP_NONE) {
        *this = VirgilAsymmetricCipher(POLARSSL_PK_ECKEY);
        POLARSSL_ERROR_HANDLER_DISPOSE(
            ::ecp_gen_key(ecTypeId, pk_ec(*(impl_->ctx)), ctr_drbg_random, &ctr_drbg),
            ::entropy_free(&entropy)
        );
    } else {
        ::entropy_free(&entropy);
        throw VirgilCryptoException("VirgilKeyPair: Unknown type of the generated Key Pair.");
    }

    ::entropy_free(&entropy);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToDER(const VirgilByteArray& pwd) const {
    checkState();
    checkPasswordLen(pwd.size());
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
    checkPasswordLen(pwd.size());
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

