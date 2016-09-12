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

#ifndef VIRGIL_CRYPTO_CONFIG_CHECK_H
#define VIRGIL_CRYPTO_CONFIG_CHECK_H

#if defined(VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_MD5) && \
    !defined(VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA1) && \
    !defined(VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA256) && \
    !defined(VIRGIL_CRYPTO_FOUNDATION_HASH_ALG_SHA512) )
#error "VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE defined, but no specific algorithm defined"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_KDF_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_KDF_ALG_KDF1) && \
    !defined(VIRGIL_CRYPTO_FOUNDATION_KDF_ALG_KDF2) )
#error "VIRGIL_CRYPTO_FOUNDATION_KDF_MODULE defined, but no specific algorithm defined"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_PBE_ALG_PKCS5_PBES2) && \
    !defined(VIRGIL_CRYPTO_FOUNDATION_PBE_ALG_PKCS12_PBE) )
#error "VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE defined, but no specific algorithm defined"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_PBKDF_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_PBKDF_ALG_PBKDF2) )
#error "VIRGIL_CRYPTO_FOUNDATION_PBKDF_MODULE defined, but no specific algorithm defined"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_ALG_AES) )
#error "VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE defined, but no specific algorithm defined"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_RSA) && \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_EC) )
#error "VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE defined, but no specific algorithm defined"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_EC) && ( \
    !defined(VIRGIL_CRYPTO_EC_SECP192R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_SECP224R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_SECP256R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_SECP384R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_SECP521R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_SECP192K1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_SECP224K1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_SECP256K1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_BP256R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_BP384R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_BP512R1_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_CURVE25519_ENABLED) && \
    !defined(VIRGIL_CRYPTO_EC_ED25519_ENABLED) )
#error "VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_ALG_EC defined, but no specific elliptic curve available"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE) )
#error "VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE defined, but not all prerequisites"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_ALG_AES) )
#error "VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE defined, but no specific algorithm defined"
#endif

#if defined(VIRGIL_CRYPTO_CIPHER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE) )
#error "VIRGIL_CRYPTO_CIPHER_MODULE defined, but not all prerequisites"
#endif

#if defined(VIRGIL_CRYPTO_STREAM_CIPHER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE) )
#error "VIRGIL_CRYPTO_STREAM_CIPHER_MODULE defined, but not all prerequisites"
#endif

#if defined(VIRGIL_CRYPTO_CHUNK_CIPHER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE) )
#error "VIRGIL_CRYPTO_CHUNK_CIPHER_MODULE defined, but not all prerequisites"
#endif

#if defined(VIRGIL_CRYPTO_TINY_CIPHER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_KDF_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE) )
#error "VIRGIL_CRYPTO_TINY_CIPHER_MODULE defined, but not all prerequisites"
#endif

#if defined(VIRGIL_CRYPTO_SIGNER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE) )
#error "VIRGIL_CRYPTO_SIGNER_MODULE defined, but not all prerequisites"
#endif

#if defined(VIRGIL_CRYPTO_STREAM_SIGNER_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_HASH_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASYMMETRIC_CIPHER_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_CMS_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE) )
#error "VIRGIL_CRYPTO_STREAM_SIGNER_MODULE defined, but not all prerequisites"
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE) && ( \
    !defined(VIRGIL_CRYPTO_FOUNDATION_RANDOM_MODULE) || \
    !defined(VIRGIL_CRYPTO_FOUNDATION_ASN1_MODULE) )
#error "VIRGIL_CRYPTO_FOUNDATION_PBE_MODULE defined, but not all prerequisites"
#endif

#endif //VIRGIL_CRYPTO_CONFIG_CHECK_H
