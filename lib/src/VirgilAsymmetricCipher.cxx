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

#include <mbedtls/config.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/PolarsslException.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/priv/VirgilAsn1Alg.h>
#include <mbedtls/asn1write.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::VirgilKeyPair;

using virgil::crypto::foundation::PolarsslException;
using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::VirgilAsymmetricCipherImpl;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::priv::VirgilAsn1Alg;

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

static VirgilKeyPair::Type key_type_from_params(size_t rsa_key_size, mbedtls_ecp_group_id ecp_group_id) {
    if (rsa_key_size > 0) {
        switch (rsa_key_size) {
            case 256:
                return VirgilKeyPair::Type_RSA_256;
            case 512:
                return VirgilKeyPair::Type_RSA_512;
            case 1024:
                return VirgilKeyPair::Type_RSA_1024;
            case 2048:
                return VirgilKeyPair::Type_RSA_2048;
            case 3072:
                return VirgilKeyPair::Type_RSA_3072;
            case 4096:
                return VirgilKeyPair::Type_RSA_4096;
            case 8192:
                return VirgilKeyPair::Type_RSA_8192;
            default:
                throw VirgilCryptoException("VirgilAsymmetricCipher: undefined RSA key length");
        }
    } else if (ecp_group_id != MBEDTLS_ECP_DP_NONE) {
        switch (ecp_group_id) {
            case MBEDTLS_ECP_DP_SECP192R1:
                return VirgilKeyPair::Type_EC_SECP192R1;
            case MBEDTLS_ECP_DP_SECP224R1:
                return VirgilKeyPair::Type_EC_SECP224R1;
            case MBEDTLS_ECP_DP_SECP256R1:
                return VirgilKeyPair::Type_EC_SECP256R1;
            case MBEDTLS_ECP_DP_SECP384R1:
                return VirgilKeyPair::Type_EC_SECP384R1;
            case MBEDTLS_ECP_DP_SECP521R1:
                return VirgilKeyPair::Type_EC_SECP521R1;
            case MBEDTLS_ECP_DP_BP256R1:
                return VirgilKeyPair::Type_EC_BP256R1;
            case MBEDTLS_ECP_DP_BP384R1:
                return VirgilKeyPair::Type_EC_BP384R1;
            case MBEDTLS_ECP_DP_BP512R1:
                return VirgilKeyPair::Type_EC_BP512R1;
            case MBEDTLS_ECP_DP_CURVE25519:
                return VirgilKeyPair::Type_EC_Curve25519;
            case MBEDTLS_ECP_DP_SECP192K1:
                return VirgilKeyPair::Type_EC_SECP192K1;
            case MBEDTLS_ECP_DP_SECP224K1:
                return VirgilKeyPair::Type_EC_SECP224K1;
            case MBEDTLS_ECP_DP_SECP256K1:
                return VirgilKeyPair::Type_EC_SECP256K1;
            default:
                throw VirgilCryptoException("VirgilAsymmetricCipher: undefined ECP type");
        }
    } else {
        throw VirgilCryptoException("VirgilAsymmetricCipher: undefined key type");
    }
}

static void key_type_set_params(
        VirgilKeyPair::Type type, int* rsa_key_size, mbedtls_ecp_group_id* ecp_group_id) {

    *rsa_key_size = 0;
    *ecp_group_id = MBEDTLS_ECP_DP_NONE;

    switch (type) {
        case VirgilKeyPair::Type_RSA_256:
            *rsa_key_size = 256;
            break;
        case VirgilKeyPair::Type_RSA_512:
            *rsa_key_size = 512;
            break;
        case VirgilKeyPair::Type_RSA_1024:
            *rsa_key_size = 1024;
            break;
        case VirgilKeyPair::Type_RSA_2048:
            *rsa_key_size = 2048;
            break;
        case VirgilKeyPair::Type_RSA_3072:
            *rsa_key_size = 3072;
            break;
        case VirgilKeyPair::Type_RSA_4096:
            *rsa_key_size = 4096;
            break;
        case VirgilKeyPair::Type_RSA_8192:
            *rsa_key_size = 8192;
            break;
        case VirgilKeyPair::Type_EC_SECP192R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP192R1;
            break;
        case VirgilKeyPair::Type_EC_SECP224R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP224R1;
            break;
        case VirgilKeyPair::Type_EC_SECP256R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case VirgilKeyPair::Type_EC_SECP384R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP384R1;
            break;
        case VirgilKeyPair::Type_EC_SECP521R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP521R1;
            break;
        case VirgilKeyPair::Type_EC_BP256R1:
            *ecp_group_id = MBEDTLS_ECP_DP_BP256R1;
            break;
        case VirgilKeyPair::Type_EC_BP384R1:
            *ecp_group_id = MBEDTLS_ECP_DP_BP384R1;
            break;
        case VirgilKeyPair::Type_EC_BP512R1:
            *ecp_group_id = MBEDTLS_ECP_DP_BP512R1;
            break;
        case VirgilKeyPair::Type_EC_M221:
            throw VirgilCryptoException("VirgilKeyPair: Not implemented curve Type_EC_M221");
        case VirgilKeyPair::Type_EC_M255:
        case VirgilKeyPair::Type_Default:
            *ecp_group_id = MBEDTLS_ECP_DP_CURVE25519;
            break;
        case VirgilKeyPair::Type_EC_M383:
            throw VirgilCryptoException("VirgilKeyPair: Not implemented curve Type_EC_M383");
        case VirgilKeyPair::Type_EC_M511:
            throw VirgilCryptoException("VirgilKeyPair: Not implemented curve Type_EC_M511");
        case VirgilKeyPair::Type_EC_SECP192K1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP192K1;
            break;
        case VirgilKeyPair::Type_EC_SECP224K1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP224K1;
            break;
        case VirgilKeyPair::Type_EC_SECP256K1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP256K1;
            break;
        default:
            throw VirgilCryptoException("VirgilAsymmetricCipher: undefined key type");
    }
}

/// @name Private section
namespace virgil { namespace crypto { namespace foundation {

class VirgilAsymmetricCipherImpl {
public:
    VirgilAsymmetricCipherImpl(mbedtls_pk_type_t pkType) : ctx(0) {
        init_(pkType);
    }

    VirgilAsymmetricCipherImpl(const VirgilAsymmetricCipherImpl& other) : ctx(0) {
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

    mbedtls_pk_type_t pkType() const {
        if (ctx != 0) {
            return mbedtls_pk_get_type(ctx);
        } else {
            return MBEDTLS_PK_NONE;
        }
    }

private:
    void init_(mbedtls_pk_type_t pkType) {
        ctx = new mbedtls_pk_context();
        mbedtls_pk_init(ctx);
        if (pkType != MBEDTLS_PK_NONE) {
            const mbedtls_pk_info_t* info = mbedtls_pk_info_from_type(pkType);
            MBEDTLS_ERROR_HANDLER_DISPOSE(
                    mbedtls_pk_setup(ctx, info),
                    free_()
            );
        }
    }

    void free_() {
        if (ctx) {
            mbedtls_pk_free(ctx);
            delete ctx;
            ctx = 0;
        }
    }

public:
    mbedtls_pk_context* ctx;
};

}}}

VirgilAsymmetricCipher::VirgilAsymmetricCipher()
        : impl_(new VirgilAsymmetricCipherImpl(MBEDTLS_PK_NONE)) {
}

VirgilAsymmetricCipher::VirgilAsymmetricCipher(int type)
        : impl_(new VirgilAsymmetricCipherImpl(static_cast<mbedtls_pk_type_t>(type))) {
}

VirgilAsymmetricCipher::VirgilAsymmetricCipher(const VirgilAsymmetricCipher& other)
        : impl_(new VirgilAsymmetricCipherImpl(other.impl_->pkType())) {
}

VirgilAsymmetricCipher& VirgilAsymmetricCipher::operator=(const VirgilAsymmetricCipher& rhs) {
    if (this == &rhs) {
        return *this;
    }
    VirgilAsymmetricCipherImpl* newImpl = new VirgilAsymmetricCipherImpl(rhs.impl_->pkType());
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

    PolarsslKeyExport(mbedtls_pk_context* ctx, Format format, Type type, const VirgilByteArray& pwd = VirgilByteArray())
            : ctx_(ctx), format_(format), type_(type), pwd_(pwd) { }

    Format format() const { return format_; }

    Type type() const { return type_; }

    int operator()(unsigned char* buf, size_t bufLen) {
        VirgilRandom random(VirgilByteArrayUtils::stringToBytes("key_export"));
        VirgilByteArray pbesAlg = VirgilAsn1Alg::buildPKCS5(random.randomize(16), random.randomize(3072, 8192));
        if (type_ == Public && format_ == PEM) {
            return mbedtls_pk_write_pubkey_pem(ctx_, buf, bufLen);
        }
        if (type_ == Public && format_ == DER) {
            return mbedtls_pk_write_pubkey_der(ctx_, buf, bufLen);
        }
        if (type_ == Private && format_ == PEM) {
            if (pwd_.empty()) {
                return mbedtls_pk_write_key_pem(ctx_, buf, bufLen);
            } else {
                return mbedtls_pk_write_key_pkcs8_pem(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pbesAlg));
            }
        }
        if (type_ == Private && format_ == DER) {
            if (pwd_.empty()) {
                return mbedtls_pk_write_key_der(ctx_, buf, bufLen);
            } else {
                return mbedtls_pk_write_key_pkcs8_der(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pbesAlg));
            }
        }
        throw std::logic_error("Unexpected PolarsslKeyExport::Format and/or PolarsslKeyExport::Type value was given.");
    }

private:
    mbedtls_pk_context* ctx_;
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
        isNotEnoughSpace = (result == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) ||
                (result == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
        if (isNotEnoughSpace) {
            exportedKey.resize(2 * exportedKey.size());
        }
    } while (isNotEnoughSpace);

    MBEDTLS_ERROR_HANDLER(result);

    size_t writtenBytes = 0;
    if (polarsslKeyExport.format() == PolarsslKeyExport::DER && result > 0) {
        // Define written bytes for DER format
        writtenBytes = result;
        // Change result's begin for DER format.
        memmove(exportedKey.data(), exportedKey.data() + exportedKey.size() - writtenBytes, writtenBytes);
    } else if (polarsslKeyExport.format() == PolarsslKeyExport::PEM && result == 0) {
        // Define written bytes for PEM format
        writtenBytes = ::strlen(reinterpret_cast<const char*>(exportedKey.data()));
    }

    exportedKey.resize(writtenBytes);
    return exportedKey;
}

template<class EncDecFunc>
VirgilByteArray processEncryptionDecryption_(
        EncDecFunc processFunc, mbedtls_pk_context* ctx, const VirgilByteArray& in) {
    const char* pers = "encrypt_decrypt";

    VirgilByteArray result(1024);
    size_t resultLen = 0;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    MBEDTLS_ERROR_HANDLER_DISPOSE(
            mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*) pers,
                    strlen(pers)),
            mbedtls_entropy_free(&entropy)
    );

    MBEDTLS_ERROR_HANDLER_DISPOSE(
            processFunc(ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(in),
                    (unsigned char*) result.data(), &resultLen, result.size(), mbedtls_ctr_drbg_random, &ctr_drbg),
            {
                mbedtls_ctr_drbg_free(&ctr_drbg);
                mbedtls_entropy_free(&entropy);
            }
    );
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    result.resize(resultLen);
    return result;
}

static VirgilByteArray fixKey(const VirgilByteArray& key) {
    VirgilByteArray pemHeaderBegin = VirgilByteArrayUtils::stringToBytes("-----BEGIN ");
    if (std::search(key.begin(), key.end(), pemHeaderBegin.begin(), pemHeaderBegin.end()) != key.end()) {
        VirgilByteArray fixedKey(key.begin(), key.end());
        fixedKey.push_back(0);
        return fixedKey;
    }
    return key;
}

/// @name Public section

size_t VirgilAsymmetricCipher::keySize() const {
    checkState();
    return mbedtls_pk_get_bitlen(impl_->ctx);
}

size_t VirgilAsymmetricCipher::keyLength() const {
    checkState();
    return mbedtls_pk_get_len(impl_->ctx);
}

bool VirgilAsymmetricCipher::isKeyPairMatch(
        const VirgilByteArray& publicKey, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    mbedtls_pk_context public_ctx;
    mbedtls_pk_init(&public_ctx);
    VirgilByteArray fixedPublicKey = fixKey(publicKey);
    MBEDTLS_ERROR_HANDLER(
            mbedtls_pk_parse_public_key(&public_ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedPublicKey))
    );

    mbedtls_pk_context private_ctx;
    mbedtls_pk_init(&private_ctx);
    VirgilByteArray fixedPrivateKey = fixKey(privateKey);
    MBEDTLS_ERROR_HANDLER_DISPOSE(
            mbedtls_pk_parse_key(&private_ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedPrivateKey),
                    VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(privateKeyPassword)),
            mbedtls_pk_free(&public_ctx);
    );

    int result = mbedtls_pk_check_pair(&public_ctx, &private_ctx);

    mbedtls_pk_free(&public_ctx);
    mbedtls_pk_free(&private_ctx);

    return result == 0;
}

bool VirgilAsymmetricCipher::checkPrivateKeyPassword(
        const VirgilByteArray& key,
        const VirgilByteArray& pwd) {

    checkPasswordLen(pwd.size());
    mbedtls_pk_context private_ctx;
    mbedtls_pk_init(&private_ctx);
    VirgilByteArray fixedKey = fixKey(key);
    int result = mbedtls_pk_parse_key(&private_ctx,
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedKey),
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd));
    mbedtls_pk_free(&private_ctx);
    return result == 0;
}

bool VirgilAsymmetricCipher::isPrivateKeyEncrypted(const VirgilByteArray& privateKey) {
    return !checkPrivateKeyPassword(privateKey, VirgilByteArray());
}

void VirgilAsymmetricCipher::setPrivateKey(const VirgilByteArray& key, const VirgilByteArray& pwd) {
    checkPasswordLen(pwd.size());
    VirgilByteArray fixedKey = fixKey(key);
    MBEDTLS_ERROR_HANDLER(
            mbedtls_pk_parse_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedKey),
                    VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd));
    );
}

void VirgilAsymmetricCipher::setPublicKey(const VirgilByteArray& key) {
    VirgilByteArray fixedKey = fixKey(key);
    MBEDTLS_ERROR_HANDLER(
            mbedtls_pk_parse_public_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedKey));
    );
}

void VirgilAsymmetricCipher::genKeyPair(VirgilKeyPair::Type type) {

    int rsaSize = 0;
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;

    key_type_set_params(type, &rsaSize, &ecTypeId);

    int result = 0;
    const char* errMsg = 0;

    const char* pers = "virgil_gen_keypair";
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    MBEDTLS_ERROR_HANDLER_CLEANUP(result,
            mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                    (const unsigned char*) pers, strlen(pers))
    );

    if (rsaSize > 0) {
        *this = VirgilAsymmetricCipher(MBEDTLS_PK_RSA);
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_rsa_gen_key(mbedtls_pk_rsa(*(impl_->ctx)), mbedtls_ctr_drbg_random,
                        &ctr_drbg, rsaSize, 65537)
        );
    } else if (ecTypeId != MBEDTLS_ECP_DP_NONE) {
        *this = VirgilAsymmetricCipher(MBEDTLS_PK_ECKEY);
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_ecp_gen_key(ecTypeId, mbedtls_pk_ec(*(impl_->ctx)),
                        mbedtls_ctr_drbg_random, &ctr_drbg)
        );
    } else {
        MBEDTLS_ERROR_MESSAGE_CLEANUP(errMsg, "VirgilKeyPair: Unknown type of the generated Key Pair.");
    }

    cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    MBEDTLS_ERROR_HANDLER(result);
    MBEDTLS_ERROR_MESSAGE_HANDLER(errMsg);
}

void VirgilAsymmetricCipher::genKeyPairFrom(const VirgilAsymmetricCipher& other) {
    other.checkState();

    int result = 0;
    const char* errMsg = 0;

    const char* pers = "virgil_gen_keypair";
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    MBEDTLS_ERROR_HANDLER_CLEANUP(result,
            mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                    (const unsigned char*) pers, strlen(pers))
    );

    *this = VirgilAsymmetricCipher(other.impl_->pkType());
    if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_RSA)) {
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_rsa_gen_key(mbedtls_pk_rsa(*(impl_->ctx)),
                        mbedtls_ctr_drbg_random, &ctr_drbg,
                        mbedtls_pk_get_bitlen(other.impl_->ctx), 65537)
        );
    } else if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_ECKEY)) {
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_ecp_gen_key(mbedtls_pk_ec(*(other.impl_->ctx))->grp.id,
                        mbedtls_pk_ec(*(impl_->ctx)),
                        mbedtls_ctr_drbg_random, &ctr_drbg)
        );
    } else {
        MBEDTLS_ERROR_MESSAGE_CLEANUP(errMsg, "VirgilKeyPair: Unknown type of the generated Key Pair.");
    }

    cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    MBEDTLS_ERROR_HANDLER(result);
    MBEDTLS_ERROR_MESSAGE_HANDLER(errMsg);
}

VirgilByteArray VirgilAsymmetricCipher::computeShared(
        const VirgilAsymmetricCipher& publicContext, const VirgilAsymmetricCipher& privateContext) {

    int result = 0;
    const char* errMsg = 0;
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_ecdh_init(&ecdh_ctx);

    const char* pers = "virgil_gen_keypair";
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ecp_keypair* public_keypair = NULL;
    mbedtls_ecp_keypair* private_keypair = NULL;


    VirgilByteArray shared(512);
    size_t sharedLen = 0;

    MBEDTLS_ERROR_HANDLER_CLEANUP(result,
            mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                    (const unsigned char*) pers, strlen(pers))
    );

    if (mbedtls_pk_can_do(publicContext.impl_->ctx, MBEDTLS_PK_ECKEY_DH) &&
            mbedtls_pk_can_do(privateContext.impl_->ctx, MBEDTLS_PK_ECKEY_DH)) {

        public_keypair = mbedtls_pk_ec(*publicContext.impl_->ctx);
        private_keypair = mbedtls_pk_ec(*privateContext.impl_->ctx);
        if (public_keypair->grp.id != private_keypair->grp.id) {
            MBEDTLS_ERROR_MESSAGE_CLEANUP(errMsg, "VirgilAsymmetricCipher: Can compute shared on different curves");
        }
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_ecp_group_copy(&ecdh_ctx.grp, &public_keypair->grp);
        );
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_ecp_copy(&ecdh_ctx.Qp, &public_keypair->Q);
        );
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_ecp_copy(&ecdh_ctx.Q, &private_keypair->Q);
        );
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_mpi_copy(&ecdh_ctx.d, &private_keypair->d);
        );
        MBEDTLS_ERROR_HANDLER_CLEANUP(result,
                mbedtls_ecdh_calc_secret(
                        &ecdh_ctx, &sharedLen, shared.data(), shared.size(), mbedtls_ctr_drbg_random, &ctr_drbg);
        );
    } else {
        MBEDTLS_ERROR_MESSAGE_CLEANUP(errMsg,
                "VirgilAsymmetricCipher: Invalid keys for DH algorithm, only EC keys are currently supported");
    }

    cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecdh_free(&ecdh_ctx);
    MBEDTLS_ERROR_HANDLER(result);
    MBEDTLS_ERROR_MESSAGE_HANDLER(errMsg);
    shared.resize(sharedLen);
    return shared;
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
    return processEncryptionDecryption_(mbedtls_pk_encrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::decrypt(const VirgilByteArray& in) const {
    checkState();
    return processEncryptionDecryption_(mbedtls_pk_decrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::sign(const VirgilByteArray& digest, int hashType) const {
    checkState();

    unsigned char sign[MBEDTLS_MPI_MAX_SIZE];
    size_t actualSignLen = 0;
    int (* f_rng)(void*, unsigned char*, size_t) = NULL;
    mbedtls_ctr_drbg_context* p_rng = NULL;
    mbedtls_entropy_context* entropy = NULL;

    /**
     * Use pseudo random functionality for RSA and and non deterministic EC
     */
    bool useRandom =
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
            mbedtls_pk_get_type(impl_->ctx) == MBEDTLS_PK_RSA ||
                    mbedtls_pk_get_type(impl_->ctx) == MBEDTLS_PK_RSA_ALT ||
                    mbedtls_pk_get_type(impl_->ctx) == MBEDTLS_PK_RSASSA_PSS;
#else
    true;
#endif /* defined(MBEDTLS_ECDSA_DETERMINISTIC) */

    if (useRandom) {
        const char* pers = "sign";

        entropy = new mbedtls_entropy_context();
        mbedtls_entropy_init(entropy);

        p_rng = new mbedtls_ctr_drbg_context();
        mbedtls_ctr_drbg_init(p_rng);

        MBEDTLS_ERROR_HANDLER_DISPOSE(
                mbedtls_ctr_drbg_seed(p_rng, mbedtls_entropy_func, entropy,
                        (const unsigned char*) pers, strlen(pers)),
                {
                    mbedtls_ctr_drbg_free(p_rng);
                    delete p_rng;
                    p_rng = NULL;
                    mbedtls_entropy_free(entropy);
                    delete entropy;
                    entropy = NULL;
                }
        );

        f_rng = mbedtls_ctr_drbg_random;
    }

    MBEDTLS_ERROR_HANDLER_DISPOSE(
            mbedtls_pk_sign(impl_->ctx, static_cast<mbedtls_md_type_t>(hashType),
                    VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(digest), sign, &actualSignLen, f_rng, p_rng),
            {
                if (p_rng) {
                    mbedtls_ctr_drbg_free(p_rng);
                }
                if (entropy) {
                    mbedtls_entropy_free(entropy);
                }
            }
    );

    if (p_rng) {
        mbedtls_ctr_drbg_free(p_rng);
        delete p_rng;
    }
    if (entropy) {
        mbedtls_entropy_free(entropy);
        delete entropy;
    }
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(sign, actualSignLen);
}

bool VirgilAsymmetricCipher::verify(const VirgilByteArray& digest, const VirgilByteArray& sign, int hashType) const {
    checkState();
    return mbedtls_pk_verify(impl_->ctx, static_cast<mbedtls_md_type_t>(hashType),
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(digest), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(sign)) == 0;
}

VirgilKeyPair::Type VirgilAsymmetricCipher::getKeyType() const {
    checkState();
    if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_RSA)) {
        return key_type_from_params(mbedtls_pk_get_bitlen(impl_->ctx), MBEDTLS_ECP_DP_NONE);
    } else if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_ECKEY)) {
        return key_type_from_params(0, mbedtls_pk_ec(*impl_->ctx)->grp.id);
    } else {
        throw VirgilCryptoException("VirgilAsymmetricCipher: undefined key type");
    }
}

void VirgilAsymmetricCipher::setKeyType(VirgilKeyPair::Type keyType) {
    int rsaSize = 0;
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;
    key_type_set_params(keyType, &rsaSize, &ecTypeId);

    if (rsaSize > 0) {
        *this = VirgilAsymmetricCipher(MBEDTLS_PK_RSA);
    } else {
        *this = VirgilAsymmetricCipher(MBEDTLS_PK_ECKEY);
        MBEDTLS_ERROR_HANDLER(
                mbedtls_ecp_group_load(&mbedtls_pk_ec(*impl_->ctx)->grp, ecTypeId)
        );
    }
}

VirgilByteArray VirgilAsymmetricCipher::getPublicKeyBits() const {
    if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_RSA)) {
        throw VirgilCryptoException("VirgilAsymmetricCipher: operation is not supported for RSA keys");
    } else if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_ECKEY)) {
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->ctx);
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                unsigned char q[32];
                MBEDTLS_ERROR_HANDLER(
                        mbedtls_mpi_write_binary(&ecp->Q.X, q, sizeof(q))
                );
                return VirgilByteArray(q, q + sizeof(q));
            }
            default:
                throw VirgilCryptoException(
                        "VirgilAsymmetricCipher: limited support for EC keys (only Curve25519 currently supported)");
        }
    } else {
        throw VirgilCryptoException("VirgilAsymmetricCipher: undefined key type");
    }
}

void VirgilAsymmetricCipher::setPublicKeyBits(const VirgilByteArray& bits) {
    checkState();
    if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_RSA)) {
        throw VirgilCryptoException("VirgilAsymmetricCipher: operation is not supported for RSA keys");
    } else if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_ECKEY)) {
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->ctx);
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                if (bits.size() != 32) {
                    throw VirgilCryptoException("VirgilAsymmetricCipher: invalid size of Curve25519 public key");
                }
                MBEDTLS_ERROR_HANDLER(
                        mbedtls_mpi_read_binary(&ecp->Q.X, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(bits))
                );
                MBEDTLS_ERROR_HANDLER(
                        mbedtls_mpi_lset(&ecp->Q.Y, 0)
                );
                MBEDTLS_ERROR_HANDLER(
                        mbedtls_mpi_lset(&ecp->Q.Z, 1)
                );
                break;
            }
            default:
                throw VirgilCryptoException(
                        "VirgilAsymmetricCipher: limited support for EC keys (only Curve25519 currently supported)");
        }
    } else {
        throw VirgilCryptoException("VirgilAsymmetricCipher: undefined key type");
    }
}

VirgilByteArray VirgilAsymmetricCipher::signToBits(const VirgilByteArray& sign) {
    checkState();
    if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_RSA)) {
        throw VirgilCryptoException("VirgilAsymmetricCipher: operation is not supported for RSA keys");
    } else if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_ECKEY)) {
        if (sign.empty()) {
            return VirgilByteArray();
        }
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->ctx);
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                int errCode = 0;
                size_t len = 0;
                unsigned char signature[64];

                mbedtls_mpi r, s;
                mbedtls_mpi_init(&r);
                mbedtls_mpi_init(&s);

                unsigned char* p = (unsigned char*) &sign[0];
                const unsigned char* end = p + sign.size();
                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
                );
                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_asn1_get_mpi(&p, end, &r)
                );
                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_asn1_get_mpi(&p, end, &s)
                );

                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_mpi_write_binary(&r, signature, 32)
                );
                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_mpi_write_binary(&s, signature + 32, 32)
                );

                cleanup:
                mbedtls_mpi_free(&r);
                mbedtls_mpi_free(&s);
                if (errCode < 0) {
                    throw VirgilCryptoException("VirgilAsymmetricCipher: signature is malformed");
                }
                return VirgilByteArray(signature, signature + sizeof(signature));
            }
            default:
                throw VirgilCryptoException(
                        "VirgilAsymmetricCipher: limited support for EC keys (only Curve25519 currently supported)");
        }
    } else {
        throw VirgilCryptoException("VirgilAsymmetricCipher: undefined key type");
    }
}

VirgilByteArray VirgilAsymmetricCipher::signFromBits(const VirgilByteArray& bits) {
    checkState();
    if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_RSA)) {
        throw VirgilCryptoException("VirgilAsymmetricCipher: operation is not supported for RSA keys");
    } else if (mbedtls_pk_can_do(impl_->ctx, MBEDTLS_PK_ECKEY)) {
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->ctx);
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                if (bits.size() != 64) {
                    throw VirgilCryptoException("VirgilAsymmetricCipher: invalid size of Curve25519 sign");
                }
                int errCode = 0;
                size_t len = 0;
                unsigned char asn1[64 + 8 /* asn1 overhead*/];
                const size_t asn1_len = sizeof(asn1);
                unsigned char* p = asn1 + asn1_len;
                unsigned char* start = asn1;
                const unsigned char* signature = &bits[0];

                mbedtls_mpi r, s;
                mbedtls_mpi_init(&r);
                mbedtls_mpi_init(&s);

                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_mpi_read_binary(&r, signature, 32)
                );
                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_mpi_read_binary(&s, signature + 32, 32)
                );

                len = 0;
                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_asn1_write_mpi(&p, start, &s)
                );
                len += errCode;

                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_asn1_write_mpi(&p, start, &r)
                );
                len += errCode;

                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_asn1_write_len(&p, start, len)
                );

                MBEDTLS_ERROR_HANDLER_CLEANUP(errCode,
                        mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
                );

                cleanup:
                mbedtls_mpi_free(&r);
                mbedtls_mpi_free(&s);
                if (errCode < 0) {
                    throw VirgilCryptoException("VirgilAsymmetricCipher: signature bits is malformed");
                }
                return VirgilByteArray(p, asn1 + asn1_len);
            }
            default:
                throw VirgilCryptoException(
                        "VirgilAsymmetricCipher: limited support for EC keys (only Curve25519 currently supported)");
        }
    } else {
        throw VirgilCryptoException("VirgilAsymmetricCipher: undefined key type");
    }
}

size_t VirgilAsymmetricCipher::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    const char* oid = 0;
    size_t oidLen;
    size_t len = 0;
    if (impl_->pkType() == MBEDTLS_PK_ECKEY && mbedtls_pk_ec(*impl_->ctx)->grp.id != MBEDTLS_ECP_DP_NONE) {
        MBEDTLS_ERROR_HANDLER(
                mbedtls_oid_get_oid_by_ec_grp(mbedtls_pk_ec(*impl_->ctx)->grp.id, &oid, &oidLen)
        );
        len += asn1Writer.writeOID(std::string(oid, oidLen));
    } else {
        len += asn1Writer.writeNull();
    }
    MBEDTLS_ERROR_HANDLER(
            mbedtls_oid_get_oid_by_pk_alg(impl_->pkType(), &oid, &oidLen)
    );
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);
    return len + childWrittenBytes;
}

void VirgilAsymmetricCipher::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();
    std::string oid = asn1Reader.readOID();
    (void) asn1Reader.readData(); // Ignore params

    mbedtls_asn1_buf oidAsn1Buf;
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char*>(const_cast<std::string::pointer>(oid.c_str()));

    mbedtls_pk_type_t type = MBEDTLS_PK_NONE;
    MBEDTLS_ERROR_HANDLER(
            mbedtls_oid_get_pk_alg(&oidAsn1Buf, &type)
    );

    *this = VirgilAsymmetricCipher(type);
}

void VirgilAsymmetricCipher::checkState() const {
    if (impl_->pkType() == MBEDTLS_PK_NONE) {
        throw VirgilCryptoException(std::string("VirgilAsymmetricCipher: object has undefined algorithm.") +
                " Use one of the factory methods or method 'fromAsn1' to define PK algorithm.");
    }
}

