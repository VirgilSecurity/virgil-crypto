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

#ifndef VIRGIL_CRYPTO_CONFIG_H
#define VIRGIL_CRYPTO_CONFIG_H

/**
 * @name CONFIG: Foundation modules
 *
 * This section sets system specific settings.
 * \{
 */

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE
 *
 * Enable VirgilHash module that provides message digest algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilHash.h
 *
 * Requires:
 *     - at least one of VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_*
 */
#define VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_HMAC_MODULE
 *
 * Enable HMAC algorithms in the VirgilHash module.
 *
 * Module: virgil/crypto/foundation/VirgilHash.h
 *
 * Requires:
 *     - at least one of VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_*
 */
#define VIRGIL_CRYPTO_FOUNDATION_HMAC_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_MD5
 *
 * Enable the MD5 hash algorithm.
 *
 * Module: virgil/crypto/foundation/VirgilHash.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_MD5

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA1
 *
 * Enable the SHA1 hash algorithm.
 *
 * Module: virgil/crypto/foundation/VirgilHash.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA1

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA256
 *
 * Enable the SHA-224 and SHA-256 hash algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilHash.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA256

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA512
 *
 * Enable the SHA-384 and SHA-512 hash algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilHash.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA512

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_BASE64_MODULE
 *
 * Enable module that provides Base64 algorithm.
 *
 * Module: virgil/crypto/foundation/VirgilHash.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_BASE64_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_KDF_MODULE
 *
 * Enable VirgilKDF module that provides key derivation function algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilKDF.h
 *
 * Requires:
 *     - at least one of VIRGIL_CRYPTO_FOUNDATION_KDF_ALG_*
 */
#define VIRGIL_CRYPTO_FOUNDATION_KDF_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_KDF_ALG_KDF1
 *
 * Enable the KDF1 (ISO-18033-2) key derivation function algorithm.
 *
 * Module: virgil/crypto/foundation/VirgilKDF.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_KDF_ALG_KDF1

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_KDF_ALG_KDF2
 *
 * Enable the KDF2 (ISO-18033-2) key derivation function algorithm.
 *
 * Module: virgil/crypto/foundation/VirgilKDF.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_KDF_ALG_KDF2

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE
 *
 * Enable VirgilPBE module that provides password-based cryptography algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilPBE.h
 *
 * Requires:
 *     - at least one of VIRGIL_CRYPTO_FOUNDATION_PBE_ALG_*
 *     - VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE
 */
#define VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_PBE_ALG_PBES2
 *
 * Enable PBES2 algorithm from PKCS#5 standard.
 *
 * Module: virgil/crypto/foundation/VirgilPBE.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_PBE_ALG_PKCS5_PBES2

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_PBE_ALG_PKCS5_PBES2
 *
 * Enable PBE algorithm from PKCS#12 standard.
 *
 * Module: virgil/crypto/foundation/VirgilPBE.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_PBE_ALG_PKCS12_PBE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_PBKDF_MODULE
 *
 * Enable VirgilPBKDF module that provides password-based key derivation function algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilPBKDF.h
 *
 * Requires:
 *     - at least one of VIRGIL_CRYPTO_FOUNDATION_PBKDF_ALG_*
 */
#define VIRGIL_CRYPTO_FOUNDATION_PBKDF_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_PBKDF_ALG_PBKDF2
 *
 * Enable the PBKDF2 (PKCS#5) password-based key derivation function algorithm.
 *
 * Module: virgil/crypto/foundation/VirgilPBKDF.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_PBKDF_ALG_PBKDF2

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE
 *
 * Enable module that provides secure randomization.
 *
 * Module: virgil/crypto/foundation/VirgilRandom.h
 */
#define VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE
 *
 * Enable module that provides symmetric encryption algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilSymmetricCipher.h
 *
 * Requires:
 *     - at least one of VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_ALG_*
 */
#define VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE

/**
 * def VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_ALG_AES
 *
 * Enable the AES symmetric encryption algorithm.
 */
#define VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_ALG_AES

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE
 *
 * Enable module that provides asymmetric cryptography algorithms.
 *
 * Module: virgil/crypto/foundation/VirgilAsymmetricCipher.h
 *
 * Requires:
 *     - at least one of VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_*
 */
#define VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE

/**
 * def VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_RSA
 *
 * Enable the RSA asymmetric cryptography algorithms.
 */
#define VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_RSA

/**
 * def VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_EC
 *
 * Enable the Elliptic Curves asymmetric cryptography algorithms.
 * 
 * Requires:
 *     - at least one of 
 */
#define VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_EC

/**
 * @def VIRGIL_CRYPTO_EC_SECP192R1_ENABLED
 *
 * Enables 192-bits NIST curve.
 */
#define VIRGIL_CRYPTO_EC_SECP192R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_SECP224R1_ENABLED
 *
 * Enables 224-bits NIST curve.
 */
#define VIRGIL_CRYPTO_EC_SECP224R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_SECP256R1_ENABLED
 *
 * Enables 256-bits NIST curve.
 */
#define VIRGIL_CRYPTO_EC_SECP256R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_SECP384R1_ENABLED
 *
 * Enables 384-bits NIST curve.
 */
#define VIRGIL_CRYPTO_EC_SECP384R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_SECP521R1_ENABLED
 *
 * Enables 521-bits NIST curve.
 */
#define VIRGIL_CRYPTO_EC_SECP521R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_SECP192K1_ENABLED
 *
 * Enables 192-bits "Koblitz" curve.
 */
#define VIRGIL_CRYPTO_EC_SECP192K1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_SECP224K1_ENABLED
 *
 * Enables 224-bits "Koblitz" curve.
 */
#define VIRGIL_CRYPTO_EC_SECP224K1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_SECP256K1_ENABLED
 *
 * Enables 256-bits "Koblitz" curve.
 */
#define VIRGIL_CRYPTO_EC_SECP256K1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_BP256R1_ENABLED
 *
 * Enables 256-bits Brainpool curve.
 */
#define VIRGIL_CRYPTO_EC_BP256R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_BP384R1_ENABLED
 *
 * Enables 384-bits Brainpool curve.
 */
#define VIRGIL_CRYPTO_EC_BP384R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_BP512R1_ENABLED
 *
 * Enables 512-bits Brainpool curve.
 */
#define VIRGIL_CRYPTO_EC_BP512R1_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_CURVE25519_ENABLED
 *
 * Enables Curve25519 curve.
 */
#define VIRGIL_CRYPTO_EC_CURVE25519_ENABLED

/**
 * @def VIRGIL_CRYPTO_EC_ED25519_ENABLED
 *
 * Enables Ed25519 curve.
 */
#define VIRGIL_CRYPTO_EC_ED25519_ENABLED

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE
 *
 * Enable CMS (RFC 5652) module.
 */
#define VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE

/**
 * @def VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE
 *
 * Enables ASN.1 module.
 */
#define VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE

/** \} name CONFIG: Foundation modules */


/**
 * @name CONFIG: Virgil Crypto Solution modules
 *
 * This section sets system specific settings.
 * \{
 */

/**
 * @def VIRGIL_CRYPTO_CIPHER_MODULE
 *
 * Enable VirgilCipher module that provides hybrid encryption and decryption functionality.
 *
 * Module: virgil/crypto/VirgilCipher.h
 *
 * Requires:
 *     - VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE, if "Key Recipient" is used
 *     - VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE, if "Password Recipient" is used
 *     - VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE, if CMS is used
 *     - VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE, if CMS is used for crypto agility (currently the only available)
 */
#define VIRGIL_CRYPTO_CIPHER_MODULE

/**
 * @def VIRGIL_CRYPTO_STREAM_CIPHER_MODULE
 *
 * Enable VirgilStreamCipher module that provides hybrid encryption and decryption functionality.
 *
 * Module: virgil/crypto/VirgilStreamCipher.h
 *
 * Requires:
 *     - VIRGIL_CRYPTO_STREAM_API_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE, if "Key Recipient" is used
 *     - VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE, if "Password Recipient" is used
 *     - VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE, if CMS is used for crypto agility (currently the only available)
 *     - VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE, if CMS is used
 *
 * @note Use streams for I/O operations.
 */
#define VIRGIL_CRYPTO_STREAM_CIPHER_MODULE

/**
 * @def VIRGIL_CRYPTO_CHUNK_CIPHER_MODULE
 *
 * Enable VirgilChunkCipher module that provides encrypt and decrypt for data that splitted to chunks.
 *
 * Module: virgil/crypto/VirgilChunkCipher.h
 *
 * Requires:
 *     - VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE, if "Key Recipient" is used
 *     - VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE, if "Password Recipient" is used
 *     - VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE, if CMS is used
 *     - VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE, if CMS is used for crypto agility (currently the only available)
 */
#define VIRGIL_CRYPTO_CHUNK_CIPHER_MODULE

/**
 * @def VIRGIL_CRYPTO_TINY_CIPHER_MODULE
 *
 * Enable VirgilTinyCipher module that provides encrypt and decrypt for data that splitted to chunks.
 *
 * Module: virgil/crypto/VirgilTinyCipher.h
 *
 * Requires:
 *     - VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_KDF_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE
 */
#define VIRGIL_CRYPTO_TINY_CIPHER_MODULE

/**
 * @def VIRGIL_CRYPTO_SIGNER_MODULE
 *
 * Enable VirgilSigner module that provides crypto sign and verify functionality.
 *
 * Module: virgil/crypto/VirgilSigner.h
 *
 * Requires:
 *     - VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE, if CMS is used for crypto agility (currently the only available)
 *     - VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE, if CMS is used
 */
#define VIRGIL_CRYPTO_SIGNER_MODULE

/**
 * @def VIRGIL_CRYPTO_STREAM_SIGNER_MODULE
 *
 * Enable VirgilStreamSigner module that provides crypto sign and verify functionality.
 *
 * Module: virgil/crypto/VirgilStreamSigner.h
 *
 * Requires:
 *     - VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE
 *     - VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE, if CMS is used for crypto agility (currently the only available)
 *     - VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE, if CMS is used
 *
 * @note Use streams for I/O operations.
 */
#define VIRGIL_CRYPTO_STREAM_SIGNER_MODULE

/** \} name CONFIG: Virgil Crypto Solution modules */

#ifndef VIRGIL_CRYPTO_CONFIG_CHECK_FILE
#include "config_check.h"
#else
#include VIRGIL_CRYPTO_CONFIG_CHECK_FILE
#endif

#endif //VIRGIL_CRYPTO_CONFIG_H
