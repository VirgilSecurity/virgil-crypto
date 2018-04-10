/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

#include <algorithm>
#include <cstring>

#include <mbedtls/config.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/kdf2.h>
#include <mbedtls/md.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include "VirgilAsn1Alg.h"

#include "utils.h"
#include "mbedtls_context.h"

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;

using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::internal::VirgilAsn1Alg;

using virgil::crypto::foundation::internal::mbedtls_context;
using virgil::crypto::foundation::internal::mbedtls_context_policy;

#include <cstdio>

extern "C" {

typedef struct {
    unsigned char keyMaterial[MBEDTLS_CTR_DRBG_ENTROPY_LEN];
    size_t left;
} key_material_entropy_t;

int key_material_entropy_seed (void *ctx, unsigned char *seed, size_t seed_len) {

    key_material_entropy_t *entropy_ctx = (key_material_entropy_t *)(ctx);

    if (seed_len > entropy_ctx->left) {
        return -1;
    }

    memcpy (seed, entropy_ctx->keyMaterial, seed_len);
    entropy_ctx->left -= seed_len;

    return 0;
}

void key_material_entropy_reset (key_material_entropy_t *ctx) {
    if (ctx) {
        ctx->left = sizeof (ctx->keyMaterial);
    }
}

size_t key_material_entropy_len (key_material_entropy_t *ctx) {
    (void)ctx;
    return MBEDTLS_CTR_DRBG_ENTROPY_LEN;
}

}

namespace virgil { namespace crypto { namespace foundation { namespace internal {

/**
 * Universal low-level key generation function.
 *
 * @param pk_ctx       context to be fullfiled with a new key
 * @param ctr_drbg_ctx random context to be used for key generation
 * @param rsa_size     if >0 then RSA key will be generated
 * @param rsa_exponent if !=
 * @param ecp_group_id if != MBEDTLS_ECP_DP_NONE then EC key will be generated
 * @param fast_ec_type if != MBEDTLS_FAST_EC_NONE then Fast EC key will be generated
 */
void gen_key_pair(
        mbedtls_context<mbedtls_pk_context>& pk_ctx,
        mbedtls_context<mbedtls_ctr_drbg_context>& ctr_drbg_ctx, unsigned int rsa_size, int rsa_exponent,
        mbedtls_ecp_group_id ecp_group_id, mbedtls_fast_ec_type_t fast_ec_type) {

    if (rsa_size > 0) {
        pk_ctx.clear().setup(MBEDTLS_PK_RSA);
        system_crypto_handler(
                mbedtls_rsa_gen_key(
                        mbedtls_pk_rsa(*(pk_ctx.get())), mbedtls_ctr_drbg_random,
                        ctr_drbg_ctx.get(), rsa_size, rsa_exponent),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
    } else if (ecp_group_id != MBEDTLS_ECP_DP_NONE) {
        pk_ctx.clear().setup(MBEDTLS_PK_ECKEY);
        system_crypto_handler(
                mbedtls_ecp_gen_key(
                        ecp_group_id, mbedtls_pk_ec(*(pk_ctx.get())),
                        mbedtls_ctr_drbg_random, ctr_drbg_ctx.get()),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
    } else if (fast_ec_type != MBEDTLS_FAST_EC_NONE) {
        pk_ctx.clear().setup(mbedtls_pk_from_fast_ec_type(fast_ec_type));
        system_crypto_handler(
                mbedtls_fast_ec_setup(
                        mbedtls_pk_fast_ec(*(pk_ctx.get())),
                        mbedtls_fast_ec_info_from_type(
                                mbedtls_pk_fast_ec_type(
                                        mbedtls_pk_get_type(pk_ctx.get())))),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
        system_crypto_handler(
                mbedtls_fast_ec_gen_key(
                        mbedtls_pk_fast_ec(*(pk_ctx.get())),
                        mbedtls_ctr_drbg_random, ctr_drbg_ctx.get()),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
    }
}

template<class EncDecFunc>
VirgilByteArray processEncryptionDecryption(
        EncDecFunc processEncryptionOrDecryption,
        mbedtls_pk_context* pk_ctx, mbedtls_ctr_drbg_context* ctr_drbg_ctx, const VirgilByteArray& in) {

    VirgilByteArray result(1024);
    size_t resultLen = 0;

    system_crypto_handler(
            processEncryptionOrDecryption(
                    pk_ctx, in.data(), in.size(), result.data(), &resultLen, result.size(),
                    mbedtls_ctr_drbg_random, ctr_drbg_ctx),
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
        return fixedKey;
    }
    return key;
}

bool isRSA(const mbedtls_pk_context* pk_ctx) {
    const auto pk_type = mbedtls_pk_get_type(pk_ctx);
    return pk_type == MBEDTLS_PK_RSA ||
           pk_type == MBEDTLS_PK_RSA_ALT ||
           pk_type == MBEDTLS_PK_RSASSA_PSS;

}

bool isEC(const mbedtls_pk_context* pk_ctx) {
    const auto pk_type = mbedtls_pk_get_type(pk_ctx);
    return pk_type == MBEDTLS_PK_ECKEY ||
           pk_type == MBEDTLS_PK_ECKEY_DH ||
           pk_type == MBEDTLS_PK_ECDSA ||
           pk_type == MBEDTLS_PK_ED25519 ||
           pk_type == MBEDTLS_PK_X25519;
}

mbedtls_context<mbedtls_ctr_drbg_context> create_deterministic_rng_ctx(const VirgilByteArray& keyMaterial) {
    mbedtls_context<mbedtls_ctr_drbg_context> drbg_ctx;
    key_material_entropy_t entropy_ctx;

    system_crypto_handler(mbedtls_kdf2(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
            keyMaterial.data(), keyMaterial.size(), entropy_ctx.keyMaterial, key_material_entropy_len(&entropy_ctx)));

    key_material_entropy_reset(&entropy_ctx);

    system_crypto_handler(mbedtls_ctr_drbg_seed (drbg_ctx.get(), key_material_entropy_seed, &entropy_ctx, NULL, 0));

    return drbg_ctx;
}

}}}}

/// @name Public section

class VirgilAsymmetricCipher::Impl {
public:
    internal::mbedtls_context <mbedtls_pk_context> pk_ctx;
    mbedtls_context<mbedtls_entropy_context> entropy_ctx;
    mbedtls_context<mbedtls_ctr_drbg_context> ctr_drbg_ctx;
};

VirgilAsymmetricCipher::VirgilAsymmetricCipher(VirgilAsymmetricCipher&& other) noexcept = default;

VirgilAsymmetricCipher& VirgilAsymmetricCipher::operator=(VirgilAsymmetricCipher&& rhs) noexcept = default;

VirgilAsymmetricCipher::~VirgilAsymmetricCipher() noexcept = default;

VirgilAsymmetricCipher::VirgilAsymmetricCipher() : impl_(std::make_unique<Impl>()) {
    constexpr const char pers[] = "VirgilAsymmetricCipher";
    impl_->ctr_drbg_ctx.setup(mbedtls_entropy_func, impl_->entropy_ctx.get(), pers);
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
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidPublicKey)); });
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
        system_crypto_handler(
                result, [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidPrivateKey)); });
    }
    throw make_error(VirgilCryptoError::InvalidState);
}

bool VirgilAsymmetricCipher::isPrivateKeyEncrypted(const VirgilByteArray& privateKey) {
    return !checkPrivateKeyPassword(privateKey, VirgilByteArray());
}

void VirgilAsymmetricCipher::setPrivateKey(const VirgilByteArray& key, const VirgilByteArray& pwd) {
    const VirgilByteArray fixedKey = internal::fixKey(key);
    impl_->pk_ctx.clear();
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
            });
}

void VirgilAsymmetricCipher::setPublicKey(const VirgilByteArray& key) {
    const VirgilByteArray fixedKey = internal::fixKey(key);
    impl_->pk_ctx.clear();
    system_crypto_handler(
            mbedtls_pk_parse_public_key(impl_->pk_ctx.get(), fixedKey.data(), fixedKey.size()),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidPublicKey)); }
                         );
}

void VirgilAsymmetricCipher::genKeyPair(VirgilKeyPair::Type type) {
    unsigned int rsaSize = 0;
    impl_->pk_ctx.clear();
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;
    mbedtls_fast_ec_type_t fastEcType = MBEDTLS_FAST_EC_NONE;
    internal::key_type_set_params(type, &rsaSize, &ecTypeId, &fastEcType);
    internal::gen_key_pair(impl_->pk_ctx, impl_->ctr_drbg_ctx, rsaSize, 65537, ecTypeId, fastEcType);
}

void VirgilAsymmetricCipher::genKeyPairFromKeyMaterial(VirgilKeyPair::Type type, const VirgilByteArray& keyMaterial) {
    unsigned int rsaSize = 0;
    impl_->pk_ctx.clear();
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;
    mbedtls_fast_ec_type_t fastEcType = MBEDTLS_FAST_EC_NONE;
    internal::key_type_set_params(type, &rsaSize, &ecTypeId, &fastEcType);
    auto deterministic_drbg_ctx = internal::create_deterministic_rng_ctx(keyMaterial);
    internal::gen_key_pair(impl_->pk_ctx, deterministic_drbg_ctx, rsaSize, 65537, ecTypeId, fastEcType);
}

void VirgilAsymmetricCipher::genKeyPairFrom(const VirgilAsymmetricCipher& other) {
    other.checkState();
    impl_->pk_ctx.clear();

    if (mbedtls_pk_can_do(other.impl_->pk_ctx.get(), MBEDTLS_PK_RSA)) {
        internal::gen_key_pair(
                impl_->pk_ctx, impl_->ctr_drbg_ctx,
                mbedtls_pk_get_bitlen(other.impl_->pk_ctx.get()), 65537,
                MBEDTLS_ECP_DP_NONE, MBEDTLS_FAST_EC_NONE);
    } else if (mbedtls_pk_can_do(other.impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        internal::gen_key_pair(
                impl_->pk_ctx, impl_->ctr_drbg_ctx,
                0, 0, mbedtls_pk_ec(*(other.impl_->pk_ctx.get()))->grp.id,
                MBEDTLS_FAST_EC_NONE);
    } else if (mbedtls_pk_can_do(other.impl_->pk_ctx.get(), MBEDTLS_PK_X25519) ||
               mbedtls_pk_can_do(other.impl_->pk_ctx.get(), MBEDTLS_PK_ED25519)) {
        internal::gen_key_pair(
                impl_->pk_ctx, impl_->ctr_drbg_ctx,
                0, 0, MBEDTLS_ECP_DP_NONE,
                mbedtls_fast_ec_get_type(mbedtls_pk_fast_ec(*(other.impl_->pk_ctx.get()))->info));
    } else {
        throw make_error(VirgilCryptoError::InvalidState, "Algorithm is not defined in the source.");
    }
}

VirgilByteArray VirgilAsymmetricCipher::computeShared(
        const VirgilAsymmetricCipher& publicContext, const VirgilAsymmetricCipher& privateContext) {

    publicContext.checkState();
    privateContext.checkState();

    VirgilByteArray shared(521);
    size_t sharedLen = 0;

    if (mbedtls_pk_can_do(publicContext.impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY_DH) &&
        mbedtls_pk_can_do(privateContext.impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY_DH)) {

        mbedtls_ecp_keypair* public_keypair = mbedtls_pk_ec(*publicContext.impl_->pk_ctx.get());
        mbedtls_ecp_keypair* private_keypair = mbedtls_pk_ec(*privateContext.impl_->pk_ctx.get());

        if (mbedtls_ecp_is_zero(&public_keypair->Q)) {
            throw make_error(VirgilCryptoError::InvalidArgument, "Public context does not handle public key.");
        }

        if (mbedtls_mpi_cmp_int(&private_keypair->d, 0) == 0) {
            throw make_error(VirgilCryptoError::InvalidArgument, "Private context does not handle private key.");
        }

        if (public_keypair->grp.id != private_keypair->grp.id) {
            throw make_error(
                    VirgilCryptoError::InvalidArgument,
                    "Can not compute shared key if elliptic curve groups are different.");
        }

        mbedtls_context<mbedtls_ecdh_context> ecdh_ctx;

        system_crypto_handler(
                mbedtls_ecp_group_copy(&ecdh_ctx.get()->grp, &public_keypair->grp));
        system_crypto_handler(
                mbedtls_ecp_copy(&ecdh_ctx.get()->Qp, &public_keypair->Q));
        system_crypto_handler(
                mbedtls_ecp_copy(&ecdh_ctx.get()->Q, &private_keypair->Q));
        system_crypto_handler(
                mbedtls_mpi_copy(&ecdh_ctx.get()->d, &private_keypair->d));
        system_crypto_handler(
                mbedtls_ecdh_calc_secret(
                        ecdh_ctx.get(), &sharedLen, shared.data(), shared.size(),
                        mbedtls_ctr_drbg_random, publicContext.impl_->ctr_drbg_ctx.get()));
    } else if (mbedtls_pk_can_do(publicContext.impl_->pk_ctx.get(), MBEDTLS_PK_X25519) &&
               mbedtls_pk_can_do(privateContext.impl_->pk_ctx.get(), MBEDTLS_PK_X25519)) {

        mbedtls_fast_ec_keypair_t* public_keypair = mbedtls_pk_fast_ec(*publicContext.impl_->pk_ctx.get());
        mbedtls_fast_ec_keypair_t* private_keypair = mbedtls_pk_fast_ec(*privateContext.impl_->pk_ctx.get());

        sharedLen = mbedtls_fast_ec_get_shared_len(public_keypair->info);
        system_crypto_handler(
                mbedtls_fast_ec_compute_shared(public_keypair, private_keypair, shared.data(), sharedLen)
                             );
    } else {
        throw make_error(
                VirgilCryptoError::UnsupportedAlgorithm,
                "Can not compute shared key on given keys. Only elliptic curve keys are supported.");
    }
    shared.resize(sharedLen);
    return shared;
}


VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToDER() const {
    checkState();
    auto buffer = VirgilByteArray(calculateExportedPublicKeySizeMaxDER());
    int result = 0;
    system_crypto_handler(result = mbedtls_pk_write_pubkey_der(impl_->pk_ctx.get(), buffer.data(), buffer.size()));
    return adjustBufferWithDER(buffer, result);
}

VirgilByteArray VirgilAsymmetricCipher::exportPublicKeyToPEM() const {
    checkState();
    auto buffer = VirgilByteArray(calculateExportedPublicKeySizeMaxPEM());
    int result = 0;
    system_crypto_handler(result = mbedtls_pk_write_pubkey_pem(impl_->pk_ctx.get(), buffer.data(), buffer.size()));
    return adjustBufferWithPEM(buffer, result);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToDER(const VirgilByteArray& pwd) const {
    checkState();

    int result = 0;

    auto buffer = VirgilByteArray();
    if (pwd.empty()) {
        buffer.resize(calculateExportedPrivateKeySizeMaxDER(0));
        system_crypto_handler(result = mbedtls_pk_write_key_der(impl_->pk_ctx.get(), buffer.data(), buffer.size()));
    } else {
        constexpr size_t pbesEncryptionOverhead = 64;
        auto pbesParams = generateParametersPBES();
        buffer.resize(calculateExportedPrivateKeySizeMaxDER(pbesParams.size() + pbesEncryptionOverhead));
        system_crypto_handler(
                result = mbedtls_pk_write_key_pkcs8_der(
                        impl_->pk_ctx.get(), buffer.data(), buffer.size(), pwd.data(),
                        pwd.size(), pbesParams.data(), pbesParams.size()));
    }

    return adjustBufferWithDER(buffer, result);
}

VirgilByteArray VirgilAsymmetricCipher::exportPrivateKeyToPEM(const VirgilByteArray& pwd) const {
    checkState();

    int result = 0;

    auto buffer = VirgilByteArray();
    if (pwd.empty()) {
        buffer.resize(calculateExportedPrivateKeySizeMaxPEM(0));
        system_crypto_handler(result = mbedtls_pk_write_key_pem(impl_->pk_ctx.get(), buffer.data(), buffer.size()));
    } else {
        constexpr size_t pbesEncryptionOverhead = 64;
        auto pbesParams = generateParametersPBES();
        buffer.resize(calculateExportedPrivateKeySizeMaxPEM(pbesParams.size() + pbesEncryptionOverhead));
        system_crypto_handler(
                result = mbedtls_pk_write_key_pkcs8_pem(
                        impl_->pk_ctx.get(), buffer.data(), buffer.size(), pwd.data(),
                        pwd.size(), pbesParams.data(), pbesParams.size()));
    }

    return adjustBufferWithPEM(buffer, result);
}


VirgilByteArray VirgilAsymmetricCipher::encrypt(const VirgilByteArray& in) const {
    checkState();
    return internal::processEncryptionDecryption(
            mbedtls_pk_encrypt, impl_->pk_ctx.get(), impl_->ctr_drbg_ctx.get(), in);
}

VirgilByteArray VirgilAsymmetricCipher::decrypt(const VirgilByteArray& in) const {
    checkState();
    return internal::processEncryptionDecryption(
            mbedtls_pk_decrypt, impl_->pk_ctx.get(), impl_->ctr_drbg_ctx.get(), in);
}

VirgilByteArray VirgilAsymmetricCipher::sign(const VirgilByteArray& digest, int hashType) const {
    checkState();

    unsigned char sign[MBEDTLS_MPI_MAX_SIZE];
    size_t actualSignLen = 0;
    int (* f_rng)(void*, unsigned char*, size_t) = nullptr;
    mbedtls_ctr_drbg_context* p_rng = nullptr;

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
        f_rng = mbedtls_ctr_drbg_random;
        p_rng = impl_->ctr_drbg_ctx.get();
    }

    system_crypto_handler(
            mbedtls_pk_sign(
                    impl_->pk_ctx.get(), static_cast<mbedtls_md_type_t>(hashType),
                    digest.data(), digest.size(), sign, &actualSignLen, f_rng, p_rng),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });

    return VirgilByteArray(sign, sign + actualSignLen);
}

bool VirgilAsymmetricCipher::verify(const VirgilByteArray& digest, const VirgilByteArray& sign, int hashType) const {
    checkState();
    return mbedtls_pk_verify(
            impl_->pk_ctx.get(), static_cast<mbedtls_md_type_t>(hashType),
            digest.data(), digest.size(), sign.data(), sign.size()) == 0;
}

VirgilKeyPair::Type VirgilAsymmetricCipher::getKeyType() const {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_RSA)) {
        return internal::key_type_from_params(
                mbedtls_pk_get_bitlen(impl_->pk_ctx.get()), MBEDTLS_ECP_DP_NONE, MBEDTLS_FAST_EC_NONE);
    } else if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ECKEY)) {
        return internal::key_type_from_params(0, mbedtls_pk_ec(*impl_->pk_ctx.get())->grp.id, MBEDTLS_FAST_EC_NONE);
    } else if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_X25519) ||
               mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ED25519)) {
        return internal::key_type_from_params(
                0, MBEDTLS_ECP_DP_NONE,
                mbedtls_fast_ec_get_type(mbedtls_pk_fast_ec(*impl_->pk_ctx.get())->info));
    }
    throw make_error(VirgilCryptoError::InvalidState);
}

void VirgilAsymmetricCipher::setKeyType(VirgilKeyPair::Type keyType) {
    unsigned int rsaSize = 0;
    mbedtls_ecp_group_id ecTypeId = MBEDTLS_ECP_DP_NONE;
    mbedtls_fast_ec_type_t fastEcType = MBEDTLS_FAST_EC_NONE;
    internal::key_type_set_params(keyType, &rsaSize, &ecTypeId, &fastEcType);

    if (fastEcType != MBEDTLS_FAST_EC_NONE) {
        impl_->pk_ctx.clear().setup(mbedtls_pk_from_fast_ec_type(fastEcType));
        system_crypto_handler(
                mbedtls_fast_ec_setup(
                        mbedtls_pk_fast_ec(*(impl_->pk_ctx.get())),
                        mbedtls_fast_ec_info_from_type(
                                mbedtls_pk_fast_ec_type(
                                        mbedtls_pk_get_type(impl_->pk_ctx.get())))),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
    } else if (rsaSize > 0) {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(MBEDTLS_PK_RSA));
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}

VirgilByteArray VirgilAsymmetricCipher::getPublicKeyBits() const {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_X25519) ||
        mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ED25519)) {
        mbedtls_fast_ec_keypair_t* fast_ec = mbedtls_pk_fast_ec(*impl_->pk_ctx.get());
        return VirgilByteArray(fast_ec->public_key, fast_ec->public_key + mbedtls_fast_ec_get_key_len(fast_ec->info));
    } else {
        throw make_error(
                VirgilCryptoError::UnsupportedAlgorithm,
                internal::to_string(mbedtls_pk_get_type(impl_->pk_ctx.get())));
    }
}

void VirgilAsymmetricCipher::setPublicKeyBits(const VirgilByteArray& bits) {
    checkState();
    if (mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_X25519) ||
        mbedtls_pk_can_do(impl_->pk_ctx.get(), MBEDTLS_PK_ED25519)) {
        mbedtls_fast_ec_keypair_t* fast_ec = mbedtls_pk_fast_ec(*impl_->pk_ctx.get());
        if (bits.size() != mbedtls_fast_ec_get_key_len(fast_ec->info)) {
            throw make_error(VirgilCryptoError::InvalidArgument, "Set Fast EC public key with wrong size.");
        }
        std::copy(bits.begin(), bits.end(), fast_ec->public_key);
    } else {
        throw make_error(
                VirgilCryptoError::UnsupportedAlgorithm,
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
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
        len += asn1Writer.writeOID(std::string(oid, oidLen));
    } else {
        len += asn1Writer.writeNull();
    }
    system_crypto_handler(
            mbedtls_oid_get_oid_by_pk_alg(mbedtls_pk_get_type(impl_->pk_ctx.get()), &oid, &oidLen),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
    system_crypto_handler(
            mbedtls_oid_get_oid_by_pk_alg(mbedtls_pk_get_type(impl_->pk_ctx.get()), &oid, &oidLen),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });
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
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); });

    impl_->pk_ctx.clear().setup(type);
}

void VirgilAsymmetricCipher::checkState() const {
    if (mbedtls_pk_get_type(impl_->pk_ctx.get()) == MBEDTLS_PK_NONE) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
}

size_t VirgilAsymmetricCipher::calculateExportedPublicKeySizeMaxDER() const {
    return calculateExportedPrivateKeySizeMaxDER(0);
}

size_t VirgilAsymmetricCipher::calculateExportedPublicKeySizeMaxPEM() const {
    return 80 + (calculateExportedPublicKeySizeMaxDER() << 1);
}

size_t VirgilAsymmetricCipher::calculateExportedPrivateKeySizeMaxDER(size_t encryptionOverhead) const {
    const auto pk_ctx = impl_->pk_ctx.get();
    const auto keyLength = mbedtls_pk_get_len(pk_ctx) + 1;
    if (internal::isEC(pk_ctx)) {
        constexpr auto asn1Overhead = 3 /* top sequence + len */ +
                                      2 /* private key (tag + len) */ +
                                      3 /* version */ +
                                      32 /* optional OID (tag + len + OID) */ +
                                      6 /* optional public key (tag + len + tag + len) */;
        return asn1Overhead + 3 * keyLength + encryptionOverhead;
    }
    if (internal::isRSA(pk_ctx)) {
        constexpr auto asn1Overhead = 4 /* top sequence + len */ +
                                      3 /* version */ +
                                      5 /* modulus */ +
                                      7 * 4 /* (tag + len) * 7 numbers */;
        return asn1Overhead + 2 * keyLength + 5 * ((keyLength >> 1) + 1) + encryptionOverhead;
    }
    throw make_error(
            VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(mbedtls_pk_get_type(impl_->pk_ctx.get())));
}

size_t VirgilAsymmetricCipher::calculateExportedPrivateKeySizeMaxPEM(size_t encryptionOverhead) const {
    return 80 + (calculateExportedPrivateKeySizeMaxDER(encryptionOverhead) << 1);
}

VirgilByteArray VirgilAsymmetricCipher::generateParametersPBES() const {
    return VirgilAsn1Alg::buildPKCS5(
            internal::randomize(impl_->ctr_drbg_ctx, 16), internal::randomize(impl_->ctr_drbg_ctx, 3072, 8192));
}

VirgilByteArray VirgilAsymmetricCipher::adjustBufferWithDER(const VirgilByteArray& buffer, int size) {
    if (size < 0) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Size of DER structure contains error code not the size.");
    }
    return VirgilByteArray(buffer.cend() - size, buffer.cend());
}

VirgilByteArray VirgilAsymmetricCipher::adjustBufferWithPEM(const VirgilByteArray& buffer, int size) {
    if (size != 0) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Size of PEM structure contains error code, must be 0.");
    }
    return VirgilByteArray(buffer.cbegin(), std::find(buffer.cbegin(), buffer.cend(), 0x00));
}
