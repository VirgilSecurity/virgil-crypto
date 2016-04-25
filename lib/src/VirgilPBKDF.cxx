/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <virgil/crypto/foundation/VirgilPBKDF.h>

#include <string>
#include <sstream>
#include <stdexcept>

#include <mbedtls/oid.h>
#include <mbedtls/pkcs5.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/PolarsslException.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Compatible.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;

using virgil::crypto::foundation::VirgilPBKDF;
using virgil::crypto::foundation::VirgilPBKDFImpl;
using virgil::crypto::foundation::PolarsslException;
using virgil::crypto::foundation::asn1::VirgilAsn1Compatible;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

/**
 * @name Configuration constants
 */
///@{
static const unsigned int kIterationCount_Min = 2048;
///@}

static mbedtls_md_type_t hash_to_md_type(VirgilPBKDF::Hash hash) {
    switch (hash) {
        case VirgilPBKDF::Hash_SHA1: {
            return MBEDTLS_MD_SHA1;
        }
        case VirgilPBKDF::Hash_SHA224: {
            return MBEDTLS_MD_SHA224;
        }
        case VirgilPBKDF::Hash_SHA256: {
            return MBEDTLS_MD_SHA256;
        }
        case VirgilPBKDF::Hash_Default:
        case VirgilPBKDF::Hash_SHA384: {
            return MBEDTLS_MD_SHA384;
        }
        case VirgilPBKDF::Hash_SHA512: {
            return MBEDTLS_MD_SHA512;
        }
        case VirgilPBKDF::Hash_None:
        default: {
            return MBEDTLS_MD_NONE;
        }
    }
}

static VirgilPBKDF::Hash md_type_to_hash(mbedtls_md_type_t mdType) {
    switch (mdType) {
        case MBEDTLS_MD_SHA1: {
            return VirgilPBKDF::Hash_SHA1;
        }
        case MBEDTLS_MD_SHA224: {
            return VirgilPBKDF::Hash_SHA224;
        }
        case MBEDTLS_MD_SHA256: {
            return VirgilPBKDF::Hash_SHA256;
        }
        case MBEDTLS_MD_SHA384: {
            return VirgilPBKDF::Hash_SHA384;
        }
        case MBEDTLS_MD_SHA512: {
            return VirgilPBKDF::Hash_SHA512;
        }
        case MBEDTLS_MD_NONE:
        default: {
            return VirgilPBKDF::Hash_None;
        }
    }
}

VirgilPBKDF::VirgilPBKDF() : algorithm_(Algorithm_None), hash_(VirgilPBKDF::Hash_None), salt_(),
        iterationCount_(0), iterationCountMin_(kIterationCount_Min), checkRecommendations_(true) {
}

VirgilPBKDF::VirgilPBKDF(const virgil::crypto::VirgilByteArray& salt, unsigned int iterationCount)
        : algorithm_(Algorithm_Default), hash_(Hash_Default), salt_(salt),
        iterationCount_(iterationCount), iterationCountMin_(kIterationCount_Min), checkRecommendations_(true) {
}

VirgilPBKDF::~VirgilPBKDF() throw() {}

VirgilByteArray VirgilPBKDF::getSalt() const {
    return salt_;
}

unsigned int VirgilPBKDF::getIterationCount() const {
    return iterationCount_;
}

void VirgilPBKDF::setAlg(VirgilPBKDF::Algorithm alg) {
    algorithm_ = alg;
}

VirgilPBKDF::Algorithm VirgilPBKDF::getAlgorithm() const {
    return algorithm_;
}

void VirgilPBKDF::setHash(VirgilPBKDF::Hash hash) {
    hash_ = hash;
}

VirgilPBKDF::Hash VirgilPBKDF::getHash() const {
    return hash_;
}

void VirgilPBKDF::enableRecommendationsCheck() {
    checkRecommendations_ = true;
}

void VirgilPBKDF::disableRecommendationsCheck() {
    checkRecommendations_ = false;
}


VirgilByteArray VirgilPBKDF::derive(const virgil::crypto::VirgilByteArray& pwd, size_t outSize) {
    checkState();
    checkRecommendations(pwd);
    VirgilByteArray result(outSize);

    const mbedtls_md_info_t *hmacInfo = mbedtls_md_info_from_type(hash_to_md_type(hash_));
    mbedtls_md_context_t hmacCtx;
    mbedtls_md_init(&hmacCtx);
    MBEDTLS_ERROR_HANDLER_DISPOSE(
        mbedtls_md_setup(&hmacCtx, hmacInfo, 1),
        mbedtls_md_free(&hmacCtx)
    );

    switch (algorithm_) {
        case Algorithm_Default:
        case Algorithm_PBKDF2: {
            MBEDTLS_ERROR_HANDLER_DISPOSE(
                mbedtls_pkcs5_pbkdf2_hmac(&hmacCtx, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(salt_), iterationCount_, outSize, result.data()),
                mbedtls_md_free(&hmacCtx)
            );
            break;
        }
        case Algorithm_None:
        default: {
            throw std::logic_error("VirgilPBKDF: unknown state.");
        }
    }

    return result;
}

void VirgilPBKDF::checkState() const {
    if (algorithm_ == Algorithm_None || hash_ == Hash_None) {
        throw VirgilCryptoException(std::string("VirgilPBKDF: object has undefined algorithms.") +
                " Use constructor with parameters or method 'fromAsn1' to define key derivation function algorithms.");
    }
}

void VirgilPBKDF::checkRecommendations(const VirgilByteArray& pwd) const {
    if (!checkRecommendations_) {
        return;
    }
    if (pwd.empty()) {
        throw VirgilCryptoException("VirgilPBKDF: empty password is not secure");
    }
    if (salt_.empty()) {
        throw VirgilCryptoException("VirgilPBKDF: empty salt is not secure");
    }
    if (iterationCount_ < iterationCountMin_) {
        std::ostringstream errMsg;
        errMsg << "VirgilPBKDF: iteration count (" << iterationCount_ << ") is not secure, ";
        errMsg << "minimum recommended value is " << iterationCountMin_;
        throw VirgilCryptoException(errMsg.str());
    }
}

size_t VirgilPBKDF::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();

    if (algorithm_ != Algorithm_PBKDF2) {
        throw std::logic_error("VirgilPBKDF: ASN.1 write - unsupported PBKDF algorithm");
    }

    size_t len = 0;
    const char *oid = 0;
    size_t oidLen;

    // Write prf
    MBEDTLS_ERROR_HANDLER(
        mbedtls_oid_get_oid_by_md(hash_to_md_type(hash_), &oid, &oidLen)
    );

    len += asn1Writer.writeOID(std::string(oid, oidLen));
    len += asn1Writer.writeSequence(len);

    len += asn1Writer.writeInteger(static_cast<int>(iterationCount_));
    len += asn1Writer.writeOctetString(salt_);
    len += asn1Writer.writeSequence(len);
    len += asn1Writer.writeOID(std::string(MBEDTLS_OID_PKCS5_PBKDF2, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBKDF2)));
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilPBKDF::asn1Read(VirgilAsn1Reader& asn1Reader) {
    mbedtls_asn1_buf oidAsn1Buf;
    std::string oid;

    // Read key derivation function algorithm identifier
    asn1Reader.readSequence();
    oid = asn1Reader.readOID();

    if (oid != std::string(MBEDTLS_OID_PKCS5_PBKDF2, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBKDF2))) {
        throw std::logic_error("VirgilPBKDF: ASN.1 read - unsupported PBKDF algorithm");
    }

    // Read PBKDF2-Params
    asn1Reader.readSequence();
    salt_ = asn1Reader.readOctetString();
    iterationCount_ = static_cast<unsigned int>(asn1Reader.readInteger());

    // Read PRF
    asn1Reader.readSequence();
    oid = asn1Reader.readOID();
    oidAsn1Buf.len = oid.size();
    oidAsn1Buf.p = reinterpret_cast<unsigned char *>(const_cast<std::string::pointer>(oid.c_str()));

    mbedtls_md_type_t mdType = MBEDTLS_MD_NONE;
    MBEDTLS_ERROR_HANDLER(
        mbedtls_oid_get_md_alg(&oidAsn1Buf, &mdType)
    );

    algorithm_ = Algorithm_PBKDF2;
    hash_ = md_type_to_hash(mdType);
}
