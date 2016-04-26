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
#include <algorithm>

#include <mbedtls/config.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/PolarsslException.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/priv/VirgilAsn1Alg.h>

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

/// @name Private section
namespace virgil { namespace crypto { namespace foundation {

class VirgilAsymmetricCipherImpl {
public:
    VirgilAsymmetricCipherImpl(mbedtls_pk_type_t pkType) : ctx(0) {
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

    mbedtls_pk_type_t pkType() const {
        if (ctx != 0) {
            return ::mbedtls_pk_get_type(ctx);
        } else {
            return MBEDTLS_PK_NONE;
        }
    }
private:
    void init_(mbedtls_pk_type_t pkType) {
        ctx = new mbedtls_pk_context();
        ::mbedtls_pk_init(ctx);
        if (pkType != MBEDTLS_PK_NONE) {
            const mbedtls_pk_info_t * info = mbedtls_pk_info_from_type(pkType);
            MBEDTLS_ERROR_HANDLER_DISPOSE(
                ::mbedtls_pk_setup(ctx, info),
                free_()
            );
        }
    }

    void free_() {
        if (ctx) {
            ::mbedtls_pk_free(ctx);
            delete ctx;
            ctx = 0;
        }
    }

public:
    mbedtls_pk_context * ctx;
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
    PolarsslKeyExport(mbedtls_pk_context *ctx, Format format, Type type, const VirgilByteArray& pwd = VirgilByteArray())
            : ctx_(ctx), format_(format), type_(type), pwd_(pwd)  {}

    Format format() const { return format_; }
    Type type() const { return type_; }

    int operator()(unsigned char *buf, size_t bufLen) {
        VirgilRandom random(VirgilByteArrayUtils::stringToBytes("key_export"));
        VirgilByteArray pbesAlg = VirgilAsn1Alg::buildPKCS5(random.randomize(16), random.randomize(3072, 8192));
        if (type_ == Public && format_ == PEM) {
            return ::mbedtls_pk_write_pubkey_pem(ctx_, buf, bufLen);
        }
        if (type_ == Public && format_ == DER) {
            return ::mbedtls_pk_write_pubkey_der(ctx_, buf, bufLen);
        }
        if (type_ == Private && format_ == PEM) {
            if (pwd_.empty()) {
                return ::mbedtls_pk_write_key_pem(ctx_, buf, bufLen);
            } else {
                return ::mbedtls_pk_write_key_pkcs8_pem(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pbesAlg));
            }
        }
        if (type_ == Private && format_ == DER) {
            if (pwd_.empty()) {
                return ::mbedtls_pk_write_key_der(ctx_, buf, bufLen);
            } else {
                return ::mbedtls_pk_write_key_pkcs8_der(ctx_, buf, bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd_),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pbesAlg));
            }
        }
        throw std::logic_error("Unexpected PolarsslKeyExport::Format and/or PolarsslKeyExport::Type value was given.");
    }
private:
    mbedtls_pk_context *ctx_;
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
        writtenBytes = ::strlen(reinterpret_cast<const char *>(exportedKey.data()));
    }

    exportedKey.resize(writtenBytes);
    return exportedKey;
}

template <class EncDecFunc>
VirgilByteArray processEncryptionDecryption_(EncDecFunc processFunc, mbedtls_pk_context *ctx, const VirgilByteArray& in) {
    const char *pers = "encrypt_decrypt";

    VirgilByteArray result(1024);
    size_t resultLen = 0;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    ::mbedtls_ctr_drbg_init(&ctr_drbg);

    MBEDTLS_ERROR_HANDLER_DISPOSE(
        ::mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)),
        ::mbedtls_entropy_free(&entropy)
    );

    MBEDTLS_ERROR_HANDLER_DISPOSE(
        processFunc(ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(in),
                (unsigned char *)result.data(), &resultLen, result.size(), mbedtls_ctr_drbg_random, &ctr_drbg),
        {
            ::mbedtls_ctr_drbg_free(&ctr_drbg);
            ::mbedtls_entropy_free(&entropy);
        }
    );
    ::mbedtls_ctr_drbg_free(&ctr_drbg);
    ::mbedtls_entropy_free(&entropy);
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
    return ::mbedtls_pk_get_bitlen(impl_->ctx);
}

size_t VirgilAsymmetricCipher::keyLength() const {
    checkState();
    return ::mbedtls_pk_get_len(impl_->ctx);
}

bool VirgilAsymmetricCipher::isKeyPairMatch(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    mbedtls_pk_context public_ctx;
    mbedtls_pk_init(&public_ctx);
    VirgilByteArray fixedPublicKey = fixKey(publicKey);
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_pk_parse_public_key(&public_ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedPublicKey))
    );

    mbedtls_pk_context private_ctx;
    mbedtls_pk_init(&private_ctx);
    VirgilByteArray fixedPrivateKey = fixKey(privateKey);
    MBEDTLS_ERROR_HANDLER_DISPOSE(
        ::mbedtls_pk_parse_key(&private_ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedPrivateKey),
                VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(privateKeyPassword)),
        ::mbedtls_pk_free(&public_ctx);
    );

    int result = ::mbedtls_pk_check_pair(&public_ctx, &private_ctx);

    ::mbedtls_pk_free(&public_ctx);
    ::mbedtls_pk_free(&private_ctx);

    return  result == 0;
}

bool VirgilAsymmetricCipher::checkPrivateKeyPassword(const VirgilByteArray& key,
        const VirgilByteArray& pwd) {

    checkPasswordLen(pwd.size());
    mbedtls_pk_context private_ctx;
    mbedtls_pk_init(&private_ctx);
    VirgilByteArray fixedKey = fixKey(key);
    int result = ::mbedtls_pk_parse_key(&private_ctx,
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedKey), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd));
    ::mbedtls_pk_free(&private_ctx);
    return result == 0;
}

bool VirgilAsymmetricCipher::isPrivateKeyEncrypted(const VirgilByteArray& privateKey) {
    return !checkPrivateKeyPassword(privateKey, VirgilByteArray());
}

void VirgilAsymmetricCipher::setPrivateKey(const VirgilByteArray& key, const VirgilByteArray& pwd) {
    checkPasswordLen(pwd.size());
    VirgilByteArray fixedKey = fixKey(key);
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_pk_parse_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedKey), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd));
    );
}

void VirgilAsymmetricCipher::setPublicKey(const VirgilByteArray& key) {
    VirgilByteArray fixedKey = fixKey(key);
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_pk_parse_public_key(impl_->ctx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(fixedKey));
    );
}

void VirgilAsymmetricCipher::genKeyPair(VirgilKeyPair::Type type) {
    int rsaSize = 0;
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;
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
            ecTypeId = MBEDTLS_ECP_DP_SECP192R1;
            break;
        case VirgilKeyPair::Type_EC_SECP224R1:
            ecTypeId = MBEDTLS_ECP_DP_SECP224R1;
            break;
        case VirgilKeyPair::Type_EC_SECP256R1:
            ecTypeId = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case VirgilKeyPair::Type_EC_SECP384R1:
            ecTypeId = MBEDTLS_ECP_DP_SECP384R1;
            break;
        case VirgilKeyPair::Type_EC_SECP521R1:
            ecTypeId = MBEDTLS_ECP_DP_SECP521R1;
            break;
        case VirgilKeyPair::Type_EC_BP256R1:
            ecTypeId = MBEDTLS_ECP_DP_BP256R1;
            break;
        case VirgilKeyPair::Type_EC_BP384R1:
            ecTypeId = MBEDTLS_ECP_DP_BP384R1;
            break;
        case VirgilKeyPair::Type_EC_BP512R1:
            ecTypeId = MBEDTLS_ECP_DP_BP512R1;
            break;
        case VirgilKeyPair::Type_EC_M221:
            throw VirgilCryptoException("VirgilKeyPair: Not implemented curve Type_EC_M221");
            break;
        case VirgilKeyPair::Type_EC_M255:
            ecTypeId = MBEDTLS_ECP_DP_CURVE25519;
            break;
        case VirgilKeyPair::Type_EC_M383:
            throw VirgilCryptoException("VirgilKeyPair: Not implemented curve Type_EC_M383");
            break;
        case VirgilKeyPair::Type_EC_M511:
            throw VirgilCryptoException("VirgilKeyPair: Not implemented curve Type_EC_M511");
            break;
        case VirgilKeyPair::Type_EC_SECP192K1:
            ecTypeId = MBEDTLS_ECP_DP_SECP192K1;
            break;
        case VirgilKeyPair::Type_EC_SECP224K1:
            ecTypeId = MBEDTLS_ECP_DP_SECP224K1;
            break;
        case VirgilKeyPair::Type_EC_SECP256K1:
            ecTypeId = MBEDTLS_ECP_DP_SECP256K1;
            break;
        case VirgilKeyPair::Type_Default:
        default:
            ecTypeId = MBEDTLS_ECP_DP_CURVE25519;
            break;
    }

    const char *pers = "virgil_gen_keypair";
    mbedtls_entropy_context entropy;
    ::mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    ::mbedtls_ctr_drbg_init(&ctr_drbg);

    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))
    );

    if (rsaSize > 0) {
        *this = VirgilAsymmetricCipher(MBEDTLS_PK_RSA);
        MBEDTLS_ERROR_HANDLER_DISPOSE(
            ::mbedtls_rsa_gen_key(mbedtls_pk_rsa(*(impl_->ctx)), mbedtls_ctr_drbg_random, &ctr_drbg, rsaSize, 65537),
            ::mbedtls_entropy_free(&entropy)
        );
    } else if (ecTypeId != MBEDTLS_ECP_DP_NONE) {
        *this = VirgilAsymmetricCipher(MBEDTLS_PK_ECKEY);
        MBEDTLS_ERROR_HANDLER_DISPOSE(
            ::mbedtls_ecp_gen_key(ecTypeId, mbedtls_pk_ec(*(impl_->ctx)), mbedtls_ctr_drbg_random, &ctr_drbg),
            ::mbedtls_entropy_free(&entropy)
        );
    } else {
        ::mbedtls_entropy_free(&entropy);
        throw VirgilCryptoException("VirgilKeyPair: Unknown type of the generated Key Pair.");
    }

    ::mbedtls_entropy_free(&entropy);
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
    return processEncryptionDecryption_(::mbedtls_pk_encrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::decrypt(const VirgilByteArray& in) const {
    checkState();
    return processEncryptionDecryption_(::mbedtls_pk_decrypt, impl_->ctx, in);
}

VirgilByteArray VirgilAsymmetricCipher::sign(const VirgilByteArray& digest, int hashType) const {
    checkState();

    unsigned char sign[MBEDTLS_MPI_MAX_SIZE];
    size_t actualSignLen = 0;
    int (*f_rng)(void *, unsigned char *, size_t) = NULL;
    mbedtls_ctr_drbg_context *p_rng = NULL;
    mbedtls_entropy_context *entropy = NULL;

    /**
     * Use pseudo random functionality for RSA and and non deterministic EC
     */
    bool useRandom =
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
        mbedtls_pk_get_type(impl_->ctx) == MBEDTLS_PK_RSA    ||
        mbedtls_pk_get_type(impl_->ctx) == MBEDTLS_PK_RSA_ALT ||
        mbedtls_pk_get_type(impl_->ctx) == MBEDTLS_PK_RSASSA_PSS;
#else
        true;
#endif /* defined(MBEDTLS_ECDSA_DETERMINISTIC) */

    if (useRandom) {
        const char *pers = "sign";

        entropy = new mbedtls_entropy_context();
        mbedtls_entropy_init(entropy);

        p_rng = new mbedtls_ctr_drbg_context();
        mbedtls_ctr_drbg_init(p_rng);

        MBEDTLS_ERROR_HANDLER_DISPOSE(
            mbedtls_ctr_drbg_seed(p_rng, mbedtls_entropy_func, entropy,
                    (const unsigned char *)pers, strlen(pers)),
            {
                mbedtls_ctr_drbg_free(p_rng); delete p_rng; p_rng = NULL;
                mbedtls_entropy_free(entropy); delete entropy; entropy = NULL;
            }
        );

        f_rng = mbedtls_ctr_drbg_random;
    }

    MBEDTLS_ERROR_HANDLER_DISPOSE(
        ::mbedtls_pk_sign(impl_->ctx, static_cast<mbedtls_md_type_t>(hashType),
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
    return ::mbedtls_pk_verify(impl_->ctx, static_cast<mbedtls_md_type_t>(hashType),
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(digest), VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(sign)) == 0;
}

size_t VirgilAsymmetricCipher::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    const char *oid = 0;
    size_t oidLen;
    size_t len = 0;
    if (impl_->pkType() == MBEDTLS_PK_ECKEY && mbedtls_pk_ec(*impl_->ctx)->grp.id != MBEDTLS_ECP_DP_NONE) {
        MBEDTLS_ERROR_HANDLER(
            ::mbedtls_oid_get_oid_by_ec_grp(mbedtls_pk_ec(*impl_->ctx)->grp.id, &oid, &oidLen)
        );
        len += asn1Writer.writeOID(std::string(oid, oidLen));
    } else {
        len += asn1Writer.writeNull();
    }
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_oid_by_pk_alg(impl_->pkType(), &oid, &oidLen)
    );
    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);
    return len + childWrittenBytes;
}

void VirgilAsymmetricCipher::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();
    std::string oid = asn1Reader.readOID();
    (void)asn1Reader.readData(); // Ignore params

    mbedtls_asn1_buf oidAsn1Buf;
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    mbedtls_pk_type_t type = MBEDTLS_PK_NONE;
    MBEDTLS_ERROR_HANDLER(
        ::mbedtls_oid_get_pk_alg(&oidAsn1Buf, &type)
    );

    *this = VirgilAsymmetricCipher(type);
}

void VirgilAsymmetricCipher::checkState() const {
    if (impl_->pkType() == MBEDTLS_PK_NONE) {
        throw VirgilCryptoException(std::string("VirgilAsymmetricCipher: object has undefined algorithm.") +
                std::string(" Use one of the factory methods or method 'fromAsn1' to define PK algorithm."));
    }
}

