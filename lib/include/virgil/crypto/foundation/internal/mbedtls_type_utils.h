/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#ifndef VIRGIL_CRYPTO_MBEDTLS_TYPE_UTILS_H
#define VIRGIL_CRYPTO_MBEDTLS_TYPE_UTILS_H

#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/ecp.h>
#include <mbedtls/kdf.h>
#include <mbedtls/cipher.h>

#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

namespace virgil { namespace crypto { namespace foundation { namespace internal {

static inline VirgilKeyPair::Type key_type_from_params(size_t rsa_key_size, mbedtls_ecp_group_id ecp_group_id) {
    if (rsa_key_size > 0) {
        switch (rsa_key_size) {
            case 256:
                return VirgilKeyPair::Type::RSA_256;
            case 512:
                return VirgilKeyPair::Type::RSA_512;
            case 1024:
                return VirgilKeyPair::Type::RSA_1024;
            case 2048:
                return VirgilKeyPair::Type::RSA_2048;
            case 3072:
                return VirgilKeyPair::Type::RSA_3072;
            case 4096:
                return VirgilKeyPair::Type::RSA_4096;
            case 8192:
                return VirgilKeyPair::Type::RSA_8192;
            default:
                throw make_error(VirgilCryptoError::InvalidArgument, "Invalid RSA key size was specified.");
        }
    } else if (ecp_group_id != MBEDTLS_ECP_DP_NONE) {
        switch (ecp_group_id) {
            case MBEDTLS_ECP_DP_SECP192R1:
                return VirgilKeyPair::Type::EC_SECP192R1;
            case MBEDTLS_ECP_DP_SECP224R1:
                return VirgilKeyPair::Type::EC_SECP224R1;
            case MBEDTLS_ECP_DP_SECP256R1:
                return VirgilKeyPair::Type::EC_SECP256R1;
            case MBEDTLS_ECP_DP_SECP384R1:
                return VirgilKeyPair::Type::EC_SECP384R1;
            case MBEDTLS_ECP_DP_SECP521R1:
                return VirgilKeyPair::Type::EC_SECP521R1;
            case MBEDTLS_ECP_DP_BP256R1:
                return VirgilKeyPair::Type::EC_BP256R1;
            case MBEDTLS_ECP_DP_BP384R1:
                return VirgilKeyPair::Type::EC_BP384R1;
            case MBEDTLS_ECP_DP_BP512R1:
                return VirgilKeyPair::Type::EC_BP512R1;
            case MBEDTLS_ECP_DP_CURVE25519:
                return VirgilKeyPair::Type::EC_Curve25519;
            case MBEDTLS_ECP_DP_ED25519:
                return VirgilKeyPair::Type::EC_Ed25519;
            case MBEDTLS_ECP_DP_SECP192K1:
                return VirgilKeyPair::Type::EC_SECP192K1;
            case MBEDTLS_ECP_DP_SECP224K1:
                return VirgilKeyPair::Type::EC_SECP224K1;
            case MBEDTLS_ECP_DP_SECP256K1:
                return VirgilKeyPair::Type::EC_SECP256K1;
            default:
                throw make_error(VirgilCryptoError::InvalidArgument, "Unknown EC type was specified.");
        }
    } else {
        throw make_error(VirgilCryptoError::InvalidArgument, "No RSA neither EC key type was specified.");
    }
}

static inline void key_type_set_params(
        VirgilKeyPair::Type type, size_t* rsa_key_size, mbedtls_ecp_group_id* ecp_group_id) {

    *rsa_key_size = 0;
    *ecp_group_id = MBEDTLS_ECP_DP_NONE;

    switch (type) {
        case VirgilKeyPair::Type::RSA_256:
            *rsa_key_size = 256;
            break;
        case VirgilKeyPair::Type::RSA_512:
            *rsa_key_size = 512;
            break;
        case VirgilKeyPair::Type::RSA_1024:
            *rsa_key_size = 1024;
            break;
        case VirgilKeyPair::Type::RSA_2048:
            *rsa_key_size = 2048;
            break;
        case VirgilKeyPair::Type::RSA_3072:
            *rsa_key_size = 3072;
            break;
        case VirgilKeyPair::Type::RSA_4096:
            *rsa_key_size = 4096;
            break;
        case VirgilKeyPair::Type::RSA_8192:
            *rsa_key_size = 8192;
            break;
        case VirgilKeyPair::Type::EC_SECP192R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP192R1;
            break;
        case VirgilKeyPair::Type::EC_SECP224R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP224R1;
            break;
        case VirgilKeyPair::Type::EC_SECP256R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case VirgilKeyPair::Type::EC_SECP384R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP384R1;
            break;
        case VirgilKeyPair::Type::EC_SECP521R1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP521R1;
            break;
        case VirgilKeyPair::Type::EC_BP256R1:
            *ecp_group_id = MBEDTLS_ECP_DP_BP256R1;
            break;
        case VirgilKeyPair::Type::EC_BP384R1:
            *ecp_group_id = MBEDTLS_ECP_DP_BP384R1;
            break;
        case VirgilKeyPair::Type::EC_BP512R1:
            *ecp_group_id = MBEDTLS_ECP_DP_BP512R1;
            break;
        case VirgilKeyPair::Type::EC_M255:
        case VirgilKeyPair::Type::Default:
            *ecp_group_id = MBEDTLS_ECP_DP_CURVE25519;
            break;
        case VirgilKeyPair::Type::EC_SECP192K1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP192K1;
            break;
        case VirgilKeyPair::Type::EC_SECP224K1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP224K1;
            break;
        case VirgilKeyPair::Type::EC_SECP256K1:
            *ecp_group_id = MBEDTLS_ECP_DP_SECP256K1;
            break;
        case VirgilKeyPair::Type::EC_Ed25519:
            *ecp_group_id = MBEDTLS_ECP_DP_ED25519;
            break;
        default:
            throw make_error(VirgilCryptoError::InvalidArgument, "Unknown Key Pair type was given.");
    }
}

static inline std::string to_string(mbedtls_pk_type_t pk_type) noexcept {
    switch (pk_type) {
        case MBEDTLS_PK_NONE:
            return "NONE";
        case MBEDTLS_PK_RSA:
            return "RSA";
        case MBEDTLS_PK_ECKEY:
            return "ECKEY";
        case MBEDTLS_PK_ECKEY_DH:
            return "ECKEY_DH";
        case MBEDTLS_PK_ECDSA:
            return "ECDSA";
        case MBEDTLS_PK_RSA_ALT:
            return "RSA_ALT";
        case MBEDTLS_PK_RSASSA_PSS:
            return "RSASSA_PSS";
        default:
            return "UNDEFINED";
    }
}

static inline std::string to_string(mbedtls_md_type_t md_type) noexcept {
    switch (md_type) {
        case MBEDTLS_MD_NONE:
            return "NONE";
        case MBEDTLS_MD_MD2:
            return "MD2";
        case MBEDTLS_MD_MD4:
            return "MD4";
        case MBEDTLS_MD_MD5:
            return "MD5";
        case MBEDTLS_MD_SHA1:
            return "SHA1";
        case MBEDTLS_MD_SHA224:
            return "SHA224";
        case MBEDTLS_MD_SHA256:
            return "SHA256";
        case MBEDTLS_MD_SHA384:
            return "SHA384";
        case MBEDTLS_MD_SHA512:
            return "SHA512";
        case MBEDTLS_MD_RIPEMD160:
            return "RIPEMD160";
        default:
            return "UNDEFINED";
    }
}

static inline std::string to_string(mbedtls_kdf_type_t kdf_type) noexcept {
    switch (kdf_type) {
        case MBEDTLS_KDF_NONE:
            return "NONE";
        case MBEDTLS_KDF_KDF1:
            return "KDF1";
        case MBEDTLS_KDF_KDF2:
            return "KDF2";
        default:
            return "UNDEFINED";
    }
}

static inline std::string to_string(mbedtls_cipher_type_t cipher_type) noexcept {
    switch (cipher_type) {
        case MBEDTLS_CIPHER_NONE:
            return "NONE";
        case MBEDTLS_CIPHER_NULL:
            return "NULL";
        case MBEDTLS_CIPHER_AES_128_ECB:
            return "AES_128_ECB";
        case MBEDTLS_CIPHER_AES_192_ECB:
            return "AES_192_ECB";
        case MBEDTLS_CIPHER_AES_256_ECB:
            return "AES_256_ECB";
        case MBEDTLS_CIPHER_AES_128_CBC:
            return "AES_128_CBC";
        case MBEDTLS_CIPHER_AES_192_CBC:
            return "AES_192_CBC";
        case MBEDTLS_CIPHER_AES_256_CBC:
            return "AES_256_CBC";
        case MBEDTLS_CIPHER_AES_128_CFB128:
            return "AES_128_CFB128";
        case MBEDTLS_CIPHER_AES_192_CFB128:
            return "AES_192_CFB128";
        case MBEDTLS_CIPHER_AES_256_CFB128:
            return "AES_256_CFB128";
        case MBEDTLS_CIPHER_AES_128_CTR:
            return "AES_128_CTR";
        case MBEDTLS_CIPHER_AES_192_CTR:
            return "AES_192_CTR";
        case MBEDTLS_CIPHER_AES_256_CTR:
            return "AES_256_CTR";
        case MBEDTLS_CIPHER_AES_128_GCM:
            return "AES_128_GCM";
        case MBEDTLS_CIPHER_AES_192_GCM:
            return "AES_192_GCM";
        case MBEDTLS_CIPHER_AES_256_GCM:
            return "AES_256_GCM";
        case MBEDTLS_CIPHER_CAMELLIA_128_ECB:
            return "CAMELLIA_128_ECB";
        case MBEDTLS_CIPHER_CAMELLIA_192_ECB:
            return "CAMELLIA_192_ECB";
        case MBEDTLS_CIPHER_CAMELLIA_256_ECB:
            return "CAMELLIA_256_ECB";
        case MBEDTLS_CIPHER_CAMELLIA_128_CBC:
            return "CAMELLIA_128_CBC";
        case MBEDTLS_CIPHER_CAMELLIA_192_CBC:
            return "CAMELLIA_192_CBC";
        case MBEDTLS_CIPHER_CAMELLIA_256_CBC:
            return "CAMELLIA_256_CBC";
        case MBEDTLS_CIPHER_CAMELLIA_128_CFB128:
            return "CAMELLIA_128_CFB128";
        case MBEDTLS_CIPHER_CAMELLIA_192_CFB128:
            return "CAMELLIA_192_CFB128";
        case MBEDTLS_CIPHER_CAMELLIA_256_CFB128:
            return "CAMELLIA_256_CFB128";
        case MBEDTLS_CIPHER_CAMELLIA_128_CTR:
            return "CAMELLIA_128_CTR";
        case MBEDTLS_CIPHER_CAMELLIA_192_CTR:
            return "CAMELLIA_192_CTR";
        case MBEDTLS_CIPHER_CAMELLIA_256_CTR:
            return "CAMELLIA_256_CTR";
        case MBEDTLS_CIPHER_CAMELLIA_128_GCM:
            return "CAMELLIA_128_GCM";
        case MBEDTLS_CIPHER_CAMELLIA_192_GCM:
            return "CAMELLIA_192_GCM";
        case MBEDTLS_CIPHER_CAMELLIA_256_GCM:
            return "CAMELLIA_256_GCM";
        case MBEDTLS_CIPHER_DES_ECB:
            return "DES_ECB";
        case MBEDTLS_CIPHER_DES_CBC:
            return "DES_CBC";
        case MBEDTLS_CIPHER_DES_EDE_ECB:
            return "DES_EDE_ECB";
        case MBEDTLS_CIPHER_DES_EDE_CBC:
            return "DES_EDE_CBC";
        case MBEDTLS_CIPHER_DES_EDE3_ECB:
            return "DES_EDE3_ECB";
        case MBEDTLS_CIPHER_DES_EDE3_CBC:
            return "DES_EDE3_CBC";
        case MBEDTLS_CIPHER_BLOWFISH_ECB:
            return "BLOWFISH_ECB";
        case MBEDTLS_CIPHER_BLOWFISH_CBC:
            return "BLOWFISH_CBC";
        case MBEDTLS_CIPHER_BLOWFISH_CFB64:
            return "BLOWFISH_CFB64";
        case MBEDTLS_CIPHER_BLOWFISH_CTR:
            return "BLOWFISH_CTR";
        case MBEDTLS_CIPHER_ARC4_128:
            return "ARC4_128";
        case MBEDTLS_CIPHER_AES_128_CCM:
            return "AES_128_CCM";
        case MBEDTLS_CIPHER_AES_192_CCM:
            return "AES_192_CCM";
        case MBEDTLS_CIPHER_AES_256_CCM:
            return "AES_256_CCM";
        case MBEDTLS_CIPHER_CAMELLIA_128_CCM:
            return "CAMELLIA_128_CCM";
        case MBEDTLS_CIPHER_CAMELLIA_192_CCM:
            return "CAMELLIA_192_CCM";
        case MBEDTLS_CIPHER_CAMELLIA_256_CCM:
            return "CAMELLIA_256_CCM";
        default:
            return "UNDEFINED";
    }
}

static inline std::string to_string(mbedtls_ecp_group_id id) noexcept {
    switch (id) {
        case MBEDTLS_ECP_DP_NONE:
            return "ECP_DP_NONE";
        case MBEDTLS_ECP_DP_SECP192R1:
            return "ECP_DP_SECP192R1";
        case MBEDTLS_ECP_DP_SECP224R1:
            return "ECP_DP_SECP224R1";
        case MBEDTLS_ECP_DP_SECP256R1:
            return "ECP_DP_SECP256R1";
        case MBEDTLS_ECP_DP_SECP384R1:
            return "ECP_DP_SECP384R1";
        case MBEDTLS_ECP_DP_SECP521R1:
            return "ECP_DP_SECP521R1";
        case MBEDTLS_ECP_DP_BP256R1:
            return "ECP_DP_BP256R1";
        case MBEDTLS_ECP_DP_BP384R1:
            return "ECP_DP_BP384R1";
        case MBEDTLS_ECP_DP_BP512R1:
            return "ECP_DP_BP512R1";
        case MBEDTLS_ECP_DP_CURVE25519:
            return "ECP_DP_CURVE25519";
        case MBEDTLS_ECP_DP_SECP192K1:
            return "ECP_DP_SECP192K1";
        case MBEDTLS_ECP_DP_SECP224K1:
            return "ECP_DP_SECP224K1";
        case MBEDTLS_ECP_DP_SECP256K1:
            return "ECP_DP_SECP256K1";
        default:
            return "UNDEFINED";
    }
}

}}}}

#endif //VIRGIL_CRYPTO_MBEDTLS_TYPE_UTILS_H
