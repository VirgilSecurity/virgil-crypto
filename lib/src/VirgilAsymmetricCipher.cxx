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

#define MODULE_NAME "VirgilAsymmetricCipher"

#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

#include <mbedtls/config.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/asn1write.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/internal/VirgilAsn1Alg.h>

#include <virgil/crypto/internal/utils.h>
#include <virgil/crypto/foundation/internal/mbedtls_context.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;

using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::internal::VirgilAsn1Alg;

using virgil::crypto::foundation::internal::mbedtls_context;
using virgil::crypto::foundation::internal::mbedtls_context_policy;

namespace virgil { namespace crypto { namespace foundation { namespace internal {

void gen_key_pair(
        mbedtls_context<mbedtls_pk_context>& pk_ctx, size_t rsa_size, int rsa_exponent,
        mbedtls_ecp_group_id ecp_group_id) {

    mbedtls_context<mbedtls_entropy_context> entropy_ctx;
    mbedtls_context<mbedtls_ctr_drbg_context> ctr_drbg_ctx;

    constexpr char pers[] = "virgil_gen_keypair";
    ctr_drbg_ctx.setup(mbedtls_entropy_func, entropy_ctx.get(), pers);

    if (rsa_size > 0) {
        pk_ctx.clear().setup(MBEDTLS_PK_RSA);
        system_crypto_handler(
                mbedtls_rsa_gen_key(mbedtls_pk_rsa(*(pk_ctx.get())), mbedtls_ctr_drbg_random,
                        ctr_drbg_ctx.get(), rsa_size, rsa_exponent),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
    } else if (ecp_group_id != MBEDTLS_ECP_DP_NONE) {
        pk_ctx.clear().setup(MBEDTLS_PK_ECKEY);
        system_crypto_handler(
                mbedtls_ecp_gen_key(ecp_group_id, mbedtls_pk_ec(*(pk_ctx.get())),
                        mbedtls_ctr_drbg_random, ctr_drbg_ctx.get()),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
    }
}

/**
 * Convert public / private key helper.
 */
class KeyExportHelper {
public:
    typedef enum {
        DER = 0,
        PEM
    } Format;
    typedef enum {
        Public = 0,
        Private
    } Type;

    KeyExportHelper(mbedtls_pk_context* ctx, Format format, Type type, const VirgilByteArray& pwd = VirgilByteArray())
            : ctx_(ctx), format_(format), type_(type), pwd_(pwd) {}

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
                return mbedtls_pk_write_key_pkcs8_pem(ctx_, buf, bufLen, pwd_.data(), pwd_.size(),
                        pbesAlg.data(), pbesAlg.size());
            }
        }
        if (type_ == Private && format_ == DER) {
            if (pwd_.empty()) {
                return mbedtls_pk_write_key_der(ctx_, buf, bufLen);
            } else {
                return mbedtls_pk_write_key_pkcs8_der(ctx_, buf, bufLen, pwd_.data(), pwd_.size(),
                        pbesAlg.data(), pbesAlg.size());
            }
        }
        throw make_error(VirgilCryptoError::InvalidArgument, "Undefined key type or serialization format");
    }

private:
    mbedtls_pk_context* ctx_;
    Format format_;
    Type type_;
    VirgilByteArray pwd_;
};

static VirgilByteArray exportKey(KeyExportHelper& keyExportHelper) {
    VirgilByteArray exportedKey(2048);
    int result = 0;
    bool isNotEnoughSpace;
    do {
        result = keyExportHelper(exportedKey.data(), exportedKey.size());
        isNotEnoughSpace = (result == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) ||
                (result == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
        if (isNotEnoughSpace) {
            exportedKey.resize(2 * exportedKey.size());
        }
    } while (isNotEnoughSpace);

    system_crypto_handler(result,
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidState)); }
    );

    size_t writtenBytes = 0;
    if (keyExportHelper.format() == KeyExportHelper::DER && result > 0) {
        // Define written bytes for DER format
        writtenBytes += result;
        // Change result's begin for DER format.
        memmove(exportedKey.data(), exportedKey.data() + exportedKey.size() - writtenBytes, writtenBytes);
    } else if (keyExportHelper.format() == KeyExportHelper::PEM && result == 0) {
        // Define written bytes for PEM format
        writtenBytes = ::strlen(reinterpret_cast<const char*>(exportedKey.data()));
    }

    exportedKey.resize(writtenBytes);
    return exportedKey;
}

template<class EncDecFunc>
VirgilByteArray processEncryptionDecryption(
        EncDecFunc processEncryptionOrDecryption, mbedtls_pk_context* ctx, const VirgilByteArray& in) {

    VirgilByteArray result(1024);
    size_t resultLen = 0;

    mbedtls_context<mbedtls_entropy_context> entropy_ctx;
    mbedtls_context<mbedtls_ctr_drbg_context> ctr_drbg_ctx;

    constexpr char pers[] = "encrypt_decrypt";
    ctr_drbg_ctx.setup(mbedtls_entropy_func, entropy_ctx.get(), pers);

    system_crypto_handler(
            processEncryptionOrDecryption(ctx, in.data(), in.size(), result.data(), &resultLen, result.size(),
                    mbedtls_ctr_drbg_random, ctr_drbg_ctx.get()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );
    result.resize(resultLen);
    return result;
}

static VirgilByteArray fixKey(const VirgilByteArray& key) {
    VirgilByteArray pemHeaderBegin = VirgilByteArrayUtils::stringToBytes("-----BEGIN ");
    if (std::search(key.begin(), key.end(), pemHeaderBegin.begin(), pemHeaderBegin.end()) != key.end()) {
        VirgilByteArray fixedKey(key.begin(), key.end());
        fixedKey.push_back(0);
        return std::move(fixedKey);
    }
    return key;
}

}}}}

/// @name Public section

struct VirgilAsymmetricCipher::Impl {
    internal::mbedtls_context <mbedtls_pk_context> pk_ctx;
};

VirgilAsymmetricCipher::VirgilAsymmetricCipher(VirgilAsymmetricCipher&& other) = default;

VirgilAsymmetricCipher& VirgilAsymmetricCipher::operator=(VirgilAsymmetricCipher&& rhs) = default;

VirgilAsymmetricCipher::~VirgilAsymmetricCipher() noexcept = default;

VirgilAsymmetricCipher::VirgilAsymmetricCipher() : impl_(std::make_unique<Impl>()) {
}

size_t VirgilAsymmetricCipher::keySize() const {
    checkState();
    return mbedtls_pk_get_bitlen(impl_->pk_ctx.get());
}

size_t VirgilAsymmetricCipher::keyLength() const {
    checkState();
    return mbedtls_pk_get_len(impl_->pk_ctx.get());
}

bool VirgilAsymmetricCipher::isKeyPairMatch(
        const VirgilByteArray& publicKey, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    VirgilAsymmetricCipher public_ctx;
    public_ctx.setPublicKey(publicKey);

    VirgilAsymmetricCipher private_ctx;
    private_ctx.setPrivateKey(privateKey, privateKeyPassword);

    return mbedtls_pk_check_pair(public_ctx.impl_->pk_ctx.get(), private_ctx.impl_->pk_ctx.get()) == 0;
}

bool VirgilAsymmetricCipher::isPublicKeyValid(const VirgilByteArray& publicKey) {
    mbedtls_context<mbedtls_pk_context> public_ctx;
    const VirgilByteArray fixedKey = internal::fixKey(publicKey);
    return mbedtls_pk_parse_public_key(public_ctx.get(), fixedKey.data(), fixedKey.size()) == 0;
}

void VirgilAsymmetricCipher::checkPublicKey(const virgil::crypto::VirgilByteArray& publicKey) {
    mbedtls_context<mbedtls_pk_context> public_ctx;
    const VirgilByteArray fixedKey = internal::fixKey(publicKey);
    system_crypto_handler(
            mbedtls_pk_parse_public_key(public_ctx.get(), fixedKey.data(), fixedKey.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidPublicKey)); }
    );
}

bool VirgilAsymmetricCipher::checkPrivateKeyPassword(const VirgilByteArray& key, const VirgilByteArray& pwd) {
    mbedtls_context<mbedtls_pk_context> private_ctx;
    const VirgilByteArray fixedKey = internal::fixKey(key);
    const int result =
            mbedtls_pk_parse_key(private_ctx.get(), fixedKey.data(), fixedKey.size(), pwd.data(), pwd.size());
    if (result == 0) {
        return true;
    } else if (result == MBEDTLS_ERR_PK_PASSWORD_REQUIRED || result == MBEDTLS_ERR_PK_PASSWORD_MISMATCH) {
        return false;
    } else {
        system_crypto_handler(result,
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidPrivateKey)); }
        );
    }
    throw make_error(VirgilCryptoError::InvalidState);
}

bool VirgilAsymmetricCipher::isPrivateKeyEncrypted(const VirgilByteArray& privateKey) {
    return !checkPrivateKeyPassword(privateKey, VirgilByteArray());
}

void VirgilAsymmetricCipher::setPrivateKey(const VirgilByteArray& key, const VirgilByteArray& pwd) {
    const VirgilByteArray fixedKey = internal::fixKey(key);
    system_crypto_handler(
            mbedtls_pk_parse_key(impl_->pk_ctx.get(), fixedKey.data(), fixedKey.size(), pwd.data(), pwd.size()),
            [](int error) {
                switch (error) {
                    case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
                    case MBEDTLS_ERR_PK_PASSWORD_MISMATCH:
                        std::throw_with_nested(make_error(VirgilCryptoError::InvalidPrivateKeyPassword));
                    default:
                        std::throw_with_nested(make_error(VirgilCryptoError::InvalidPrivateKey));
                }
            }
    );
}

void VirgilAsymmetricCipher::setPublicKey(const VirgilByteArray& key) {
    const VirgilByteArray fixedKey = internal::fixKey(key);
    system_crypto_handler(
            mbedtls_pk_parse_public_key(impl_->pk_ctx.get(), fixedKey.data(), fixedKey.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidPublicKey)); }
    );
}

void VirgilAsymmetricCipher::genKeyPair(VirgilKeyPair::Type type) {
    size_t rsaSize = 0;
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;
    internal::key_type_set_params(type, &rsaSize, &ecTypeId);
    internal::gen_key_pair(impl_->pk_ctx, rsaSize, 65537, ecTypeId);
}

void VirgilAsymmetricCipher::genKeyPairFrom(const VirgilAsymmetricCipher& other) {
    other.checkState();

    if (mbedtls_pk_can_do(other.impl_->pk_ctx.get(), MBEDTLS_PK_RSA)) {
        internal::gen_key_pair(impl_->pk_ctx, mbedtls_pk_get_bitlen(other.impl_->pk_ctx.get()), 65537,
                MBEDTLS_ECP_DP_NONE);
    } else if (mbedtls_pk_can_do(other.impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        internal::gen_key_pair(impl_->pk_ctx, 0, 0, mbedtls_pk_ec(*(other.impl_->pk_ctx.get()))->grp.id);
    } else {
        throw make_error(VirgilCryptoError::InvalidState, "Algorithm is not defined in the source.");
    }
}

VirgilByteArray VirgilAsymmetricCipher::computeShared(
        const VirgilAsymmetricCipher& publicContext, const VirgilAsymmetricCipher& privateContext) {

    publicContext.checkState();
    privateContext.checkState();

    mbedtls_context<mbedtls_entropy_context> entropy_ctx;
    mbedtls_context<mbedtls_ctr_drbg_context> ctr_drbg_ctx;

    constexpr char pers[] = "virgil_compute_shared";
    ctr_drbg_ctx.setup(mbedtls_entropy_func, entropy_ctx.get(), pers);

    mbedtls_context<mbedtls_ecdh_context> ecdh_ctx;

    mbedtls_ecp_keypair* public_keypair = NULL;
    mbedtls_ecp_keypair* private_keypair = NULL;


    VirgilByteArray shared(521);
    size_t sharedLen = 0;

    if (mbedtls_pk_can_do(publicContext.impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY_DH) &&
            mbedtls_pk_can_do(privateContext.impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY_DH)) {

        public_keypair = mbedtls_pk_ec(*publicContext.impl_->pk_ctx.get());
        private_keypair = mbedtls_pk_ec(*privateContext.impl_->pk_ctx.get());

        if (mbedtls_ecp_is_zero(&public_keypair->Q)) {
            throw make_error(VirgilCryptoError::InvalidArgument, "Public context does not handle public key.");
        }

        if (mbedtls_mpi_cmp_int(&private_keypair->d, 0) == 0) {
            throw make_error(VirgilCryptoError::InvalidArgument, "Private context does not handle private key.");
        }

        if (public_keypair->grp.id != private_keypair->grp.id) {
            throw make_error(VirgilCryptoError::InvalidArgument,
                    "Can not compute shared key if elliptic curve groups are different.");
        }

        system_crypto_handler(
                mbedtls_ecp_group_copy(&ecdh_ctx.get()->grp, &public_keypair->grp)
        );
        system_crypto_handler(
                mbedtls_ecp_copy(&ecdh_ctx.get()->Qp, &public_keypair->Q)
        );
        system_crypto_handler(
                mbedtls_ecp_copy(&ecdh_ctx.get()->Q, &private_keypair->Q)
        );
        system_crypto_handler(
                mbedtls_mpi_copy(&ecdh_ctx.get()->d, &private_keypair->d)
        );
        system_crypto_handler(
                mbedtls_ecdh_calc_secret(ecdh_ctx.get(), &sharedLen, shared.data(), shared.size(),
                        mbedtls_ctr_drbg_random, ctr_drbg_ctx.get())
        );
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm,
                "Can not compute shared key on given keys. Only elliptic curve keys are supported.");
    }
    shared.resize(sharedLen);
    return shared;
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToDER(const VirgilByteArray& pwd) const {
    checkState();
    internal::KeyExportHelper keyExportHelper
            (impl_->pk_ctx.get(), internal::KeyExportHelper::DER, internal::KeyExportHelper::Private, pwd);
    return internal::exportKey(keyExportHelper);
}

VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToDER() const {
    checkState();
    internal::KeyExportHelper
            keyExportHelper(impl_->pk_ctx.get(), internal::KeyExportHelper::DER, internal::KeyExportHelper::Public);
    return internal::exportKey(keyExportHelper);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToPEM(const VirgilByteArray& pwd) const {
    checkState();
    internal::KeyExportHelper keyExportHelper
            (impl_->pk_ctx.get(), internal::KeyExportHelper::PEM, internal::KeyExportHelper::Private, pwd);
    return internal::exportKey(keyExportHelper);
}

VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToPEM() const {
    checkState();
    internal::KeyExportHelper
            keyExportHelper(impl_->pk_ctx.get(), internal::KeyExportHelper::PEM, internal::KeyExportHelper::Public);
    return internal::exportKey(keyExportHelper);
}

VirgilByteArray VirgilAsymmetricCipher::encrypt(const VirgilByteArray& in) const {
    checkState();
    return internal::processEncryptionDecryption(mbedtls_pk_encrypt, impl_->pk_ctx.get(), in);
}

VirgilByteArray VirgilAsymmetricCipher::decrypt(const VirgilByteArray& in) const {
    checkState();
    return internal::processEncryptionDecryption(mbedtls_pk_decrypt, impl_->pk_ctx.get(), in);
}

VirgilByteArray VirgilAsymmetricCipher::sign(const VirgilByteArray& digest, int hashType) const {
    checkState();

    unsigned char sign[MBEDTLS_MPI_MAX_SIZE];
    size_t actualSignLen = 0;
    int (* f_rng)(void*, unsigned char*, size_t) = nullptr;

    mbedtls_context<mbedtls_entropy_context> entropy_ctx;
    mbedtls_context<mbedtls_ctr_drbg_context> ctr_drbg_ctx;

    /**
     * Use pseudo random functionality for RSA and and non deterministic EC
     */
    bool useRandom =
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
            mbedtls_pk_get_type(impl_->pk_ctx.get()) == MBEDTLS_PK_RSA ||
                    mbedtls_pk_get_type(impl_->pk_ctx.get()) == MBEDTLS_PK_RSA_ALT ||
                    mbedtls_pk_get_type(impl_->pk_ctx.get()) == MBEDTLS_PK_RSASSA_PSS;
#else
    true;
#endif /* defined(MBEDTLS_ECDSA_DETERMINISTIC) */

    if (useRandom) {
        constexpr char pers[] = "sign";

        ctr_drbg_ctx.setup(mbedtls_entropy_func, entropy_ctx.get(), pers);

        f_rng = mbedtls_ctr_drbg_random;
    }

    system_crypto_handler(
            mbedtls_pk_sign(impl_->pk_ctx.get(), static_cast<mbedtls_md_type_t>(hashType),
                    digest.data(), digest.size(), sign, &actualSignLen, f_rng, ctr_drbg_ctx.get()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );

    return VirgilByteArray(sign, sign + actualSignLen);
}

bool VirgilAsymmetricCipher::verify(const VirgilByteArray& digest, const VirgilByteArray& sign, int hashType) const {
    checkState();
    return mbedtls_pk_verify(impl_->pk_ctx.get(), static_cast<mbedtls_md_type_t>(hashType),
            digest.data(), digest.size(), sign.data(), sign.size()) == 0;
}

VirgilKeyPair::Type VirgilAsymmetricCipher::getKeyType() const {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_RSA)) {
        return internal::key_type_from_params(mbedtls_pk_get_bitlen(impl_->pk_ctx.get()), MBEDTLS_ECP_DP_NONE);
    } else if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        return internal::key_type_from_params(0, mbedtls_pk_ec(*impl_->pk_ctx.get())->grp.id);
    }
    throw make_error(VirgilCryptoError::InvalidState);
}

void VirgilAsymmetricCipher::setKeyType(VirgilKeyPair::Type keyType) {
    size_t rsaSize = 0;
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;
    internal::key_type_set_params(keyType, &rsaSize, &ecTypeId);

    if (rsaSize == 0 && ecTypeId != MBEDTLS_ECP_DP_NONE) {
        impl_->pk_ctx.clear().setup(MBEDTLS_PK_ECKEY);
        system_crypto_handler(
                mbedtls_ecp_group_load(&mbedtls_pk_ec(*impl_->pk_ctx.get())->grp, ecTypeId),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
    } else if (rsaSize > 0) {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(MBEDTLS_PK_RSA));
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}

VirgilByteArray VirgilAsymmetricCipher::getPublicKeyBits() const {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->pk_ctx.get());
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                unsigned char q[32];
                system_crypto_handler(
                        mbedtls_mpi_write_binary(&ecp->Q.X, q, sizeof(q))
                );
                return VirgilByteArray(q, q + sizeof(q));
            }
            default:
                throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(ecp->grp.id));
        }
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm,
                internal::to_string(mbedtls_pk_get_type(impl_->pk_ctx.get())));
    }
}

void VirgilAsymmetricCipher::setPublicKeyBits(const VirgilByteArray& bits) {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->pk_ctx.get());
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                const size_t kCurve25519_Length = 32; // bytes
                if (bits.size() != kCurve25519_Length) {
                    throw make_error(VirgilCryptoError::InvalidPublicKey);
                }
                system_crypto_handler(
                        mbedtls_mpi_read_binary(&ecp->Q.X, bits.data(), bits.size())
                );
                system_crypto_handler(
                        mbedtls_mpi_lset(&ecp->Q.Y, 0)
                );
                system_crypto_handler(
                        mbedtls_mpi_lset(&ecp->Q.Z, 1)
                );
                break;
            }
            default:
                throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(ecp->grp.id));
        }
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm,
                internal::to_string(mbedtls_pk_get_type(impl_->pk_ctx.get())));
    }
}

VirgilByteArray VirgilAsymmetricCipher::signToBits(const VirgilByteArray& sign) {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        if (sign.empty()) {
            return VirgilByteArray();
        }
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->pk_ctx.get());
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                size_t len = 0;
                unsigned char signature[64];

                mbedtls_context<mbedtls_mpi> r;
                mbedtls_context<mbedtls_mpi> s;

                unsigned char* p = (unsigned char*) &sign[0];
                const unsigned char* end = p + sign.size();
                system_crypto_handler(
                        mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
                );
                system_crypto_handler(
                        mbedtls_asn1_get_mpi(&p, end, r.get())
                );
                system_crypto_handler(
                        mbedtls_asn1_get_mpi(&p, end, s.get())
                );

                system_crypto_handler(
                        mbedtls_mpi_write_binary(r.get(), signature, 32)
                );
                system_crypto_handler(
                        mbedtls_mpi_write_binary(s.get(), signature + 32, 32)
                );
                return VirgilByteArray(signature, signature + sizeof(signature));
            }
            default:
                throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(ecp->grp.id));
        }
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm,
                internal::to_string(mbedtls_pk_get_type(impl_->pk_ctx.get())));
    }
}

VirgilByteArray VirgilAsymmetricCipher::signFromBits(const VirgilByteArray& bits) {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*impl_->pk_ctx.get());
        switch (ecp->grp.id) {
            case MBEDTLS_ECP_DP_CURVE25519: {
                const size_t kCurve25519_SignLength = 64;
                if (bits.size() != kCurve25519_SignLength) {
                    throw make_error(VirgilCryptoError::InvalidSignature);
                }
                unsigned char asn1[64 + 8 /* asn1 overhead*/];
                const size_t asn1_len = sizeof(asn1);
                unsigned char* p = asn1 + asn1_len;
                unsigned char* start = asn1;
                const unsigned char* signature = &bits[0];

                mbedtls_context<mbedtls_mpi> r;
                mbedtls_context<mbedtls_mpi> s;

                system_crypto_handler(
                        mbedtls_mpi_read_binary(r.get(), signature, 32),
                        [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidSignature)); }
                );
                system_crypto_handler(
                        mbedtls_mpi_read_binary(s.get(), signature + 32, 32),
                        [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidSignature)); }
                );

                size_t len = 0;
                len += system_crypto_handler_get_result(
                        mbedtls_asn1_write_mpi(&p, start, s.get())
                );

                len += system_crypto_handler_get_result(
                        mbedtls_asn1_write_mpi(&p, start, r.get())
                );

                system_crypto_handler(
                        mbedtls_asn1_write_len(&p, start, len)
                );

                system_crypto_handler(
                        mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
                );
                return VirgilByteArray(p, asn1 + asn1_len);
            }
            default:
                throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(ecp->grp.id));
        }
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm,
                internal::to_string(mbedtls_pk_get_type(impl_->pk_ctx.get())));
    }
}

size_t VirgilAsymmetricCipher::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    const char* oid = 0;
    size_t oidLen;
    size_t len = 0;
    if (mbedtls_pk_get_type(impl_->pk_ctx.get()) == MBEDTLS_PK_ECKEY &&
            mbedtls_pk_ec(*impl_->pk_ctx.get())->grp.id != MBEDTLS_ECP_DP_NONE) {
        system_crypto_handler(
                mbedtls_oid_get_oid_by_ec_grp(mbedtls_pk_ec(*impl_->pk_ctx.get())->grp.id, &oid, &oidLen),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
        len += asn1Writer.writeOID(std::string(oid, oidLen));
    } else {
        len += asn1Writer.writeNull();
    }
    do {
        system_crypto_handler(
                mbedtls_oid_get_oid_by_pk_alg(mbedtls_pk_get_type(impl_->pk_ctx.get()), &oid, &oidLen),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
        system_crypto_handler(
                mbedtls_oid_get_oid_by_pk_alg(mbedtls_pk_get_type(impl_->pk_ctx.get()), &oid, &oidLen),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
    } while (0);
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
    system_crypto_handler(
            mbedtls_oid_get_pk_alg(&oidAsn1Buf, &type),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
    );

    impl_->pk_ctx.clear().setup(type);
}

void VirgilAsymmetricCipher::checkState() const {
    if (mbedtls_pk_get_type(impl_->pk_ctx.get()) == MBEDTLS_PK_NONE) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
}

