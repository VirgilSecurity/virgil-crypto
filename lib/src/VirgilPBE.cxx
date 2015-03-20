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

#include <virgil/crypto/VirgilPBE.h>
using virgil::crypto::VirgilPBE;

#include <polarssl/asn1.h>
#include <polarssl/oid.h>
#include <polarssl/pkcs5.h>
#include <polarssl/pkcs12.h>
#include <polarssl/cipher.h>
#include <polarssl/md.h>

#include <map>
#include <string>
#include <algorithm>

#include <cstring>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/PolarsslException.h>

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/asn1/VirgilAsn1Compatible.h>
using virgil::crypto::asn1::VirgilAsn1Compatible;

#include <virgil/crypto/asn1/VirgilAsn1Reader.h>
using virgil::crypto::asn1::VirgilAsn1Reader;

#include <virgil/crypto/asn1/VirgilAsn1Writer.h>
using virgil::crypto::asn1::VirgilAsn1Writer;

#include <virgil/crypto/VirgilRandom.h>
using virgil::crypto::VirgilRandom;

typedef enum {
    VIRGIL_PBE_NONE = 0,
    VIRGIL_PBE_PKCS5,
    VIRGIL_PBE_PKCS12,
    VIRGIL_PBE_PKCS12_SHA1_RC4_128
} VirgilPBEType;

namespace virgil { namespace crypto {

class VirgilPBEImpl {
public:
    VirgilPBEType type;
    VirgilRandom random;
    VirgilByteArray algId;
    asn1_buf pbeAlgOID;
    asn1_buf pbeParams;
    md_type_t mdType;
    cipher_type_t cipherType;
public:
    VirgilPBEImpl() : type(VIRGIL_PBE_NONE),
            random(virgil::str2bytes(std::string("com.virgilsecurity.VirgilPBE"))) {
    }

    explicit VirgilPBEImpl(VirgilPBEType pbeType, const VirgilByteArray& salt, size_t iterationCount) : type(pbeType),
            random(virgil::str2bytes(std::string("com.virgilsecurity.VirgilPBE"))) {
        const size_t adjustedIterationCount =
                iterationCount < VirgilPBE::kIterationCountMin ? VirgilPBE::kIterationCountMin : iterationCount;
        switch (pbeType) {
            case VIRGIL_PBE_PKCS5:
                init_(buildAlgIdPKCS5(salt, adjustedIterationCount));
                break;
            case VIRGIL_PBE_PKCS12:
                init_(buildAlgIdPKCS12(salt, adjustedIterationCount));
                break;
            default:
                throw VirgilCryptoException("VirgilPBE: Given algorithm is not supported.");
        }

    }
    explicit VirgilPBEImpl(const VirgilByteArray& pbeAlgId) : type(VIRGIL_PBE_NONE),
            random(virgil::str2bytes(std::string("com.virgilsecurity.VirgilPBE"))) {
        init_(pbeAlgId);
    }
private:
    /**
     * @brief Parse given PBE algorithm identifier and stores parsed data as local object state.
     * @note Algorithm identifier is distrubuted in ASN.1 DER encoded structure:
     *     AlgorithmIdentifier ::= SEQUENCE {
     *         algorithm OBJECT IDENTIFIER,
     *         parameters ANY DEFINED BY algorithm OPTIONAL }
     * @throw VirgilCryptoException if algorithm identifier is not supported or ASN.1 structure is corrupted.
     */
    void init_(const VirgilByteArray& pbeAlgId) {
        size_t len;
        unsigned char *p, *end;

        // Initial init
        type = VIRGIL_PBE_NONE;
        algId = pbeAlgId;
        mdType = POLARSSL_MD_NONE;
        cipherType = POLARSSL_CIPHER_NONE;
        memset (&pbeAlgOID, 0x00, sizeof(pbeAlgOID));
        memset (&pbeParams, 0x00, sizeof(pbeParams));

        // Parse ASN.1
        p = const_cast<unsigned char *>(algId.data());
        end = p + algId.size();

        POLARSSL_ERROR_HANDLER(
            ::asn1_get_alg(&p, end, &pbeAlgOID, &pbeParams)
        );

        if (oid_get_pkcs12_pbe_alg(&pbeAlgOID, &mdType, &cipherType) == 0) {
            type = VIRGIL_PBE_PKCS12;
        } else if (OID_CMP(OID_PKCS12_PBE_SHA1_RC4_128, &pbeAlgOID)) {
            type = VIRGIL_PBE_PKCS12_SHA1_RC4_128;
        } else if (OID_CMP(OID_PKCS5_PBES2, &pbeAlgOID)) {
            type = VIRGIL_PBE_PKCS5;
        } else {
            throw VirgilCryptoException("VirgilPBE: Given algorithm is not supported.");
        }
    }

    /**
     * pbes2 ::= SEQUENCE {
     *   id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13},
     *   PBES2-params ::= SEQUENCE {
     *      keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
     *      encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
     * }
     *
     * PBES2-KDFs ALGORITHM-IDENTIFIER ::=
     *    { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
     *
     * PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
     */
    VirgilByteArray buildAlgIdPKCS5(const VirgilByteArray& salt, size_t iterationCount) {
        VirgilAsn1Writer asn1Writer;
        const char *oid = 0;
        size_t oidLen;
        // Write PBES2-params
        size_t pbesLen = 0;
        {
            // Write PBES2-Enc
            cipherType = POLARSSL_CIPHER_DES_EDE3_CBC;
            POLARSSL_ERROR_HANDLER(
                ::oid_get_oid_by_cipher_alg(cipherType, &oid, &oidLen)
            );
            const cipher_info_t *cipherInfo = cipher_info_from_type(cipherType);
            if (cipherInfo == 0) {
                throw VirgilCryptoException("VirgilPBE: Given cipher is not supported.");
            }
            size_t encLen = 0;
            encLen += asn1Writer.writeOctetString(random.randomize(cipherInfo->iv_size));
            encLen += asn1Writer.writeOID(std::string(oid, oidLen));
            encLen += asn1Writer.writeSequence(encLen);
            // Write PBES2-KDF
            size_t kdfLen = 0;
            kdfLen += asn1Writer.writeInteger(iterationCount);
            kdfLen += asn1Writer.writeOctetString(salt);
            kdfLen += asn1Writer.writeSequence(kdfLen);
            kdfLen += asn1Writer.writeOID(std::string(OID_PKCS5_PBKDF2, OID_SIZE(OID_PKCS5_PBKDF2)));
            kdfLen += asn1Writer.writeSequence(kdfLen);

            pbesLen += encLen + kdfLen;
            pbesLen += asn1Writer.writeSequence(pbesLen);
        }
        // Write id-PBES2 OBJECT IDENTIFIER
        pbesLen += asn1Writer.writeOID(std::string(OID_PKCS5_PBES2, OID_SIZE(OID_PKCS5_PBES2)));
        asn1Writer.writeSequence(pbesLen);

        return asn1Writer.finish();
    }

    /**
     * pkcs-12Pbe ::= SEQUENCE {
     *   pkcs-12PbeId OBJECT IDENTIFIER ::= {{pkcs-12PbeIds}},
     *   pkcs-12PbeParams ::= SEQUENCE {
     *       salt        OCTET STRING,
     *       iterations  INTEGER
     *   }
     * }
     */
    VirgilByteArray buildAlgIdPKCS12(const VirgilByteArray& salt, size_t iterationCount) {
        VirgilAsn1Writer asn1Writer;
        const char *oid = 0;
        size_t oidLen;
        // Write PBE-params
        size_t pbesLen = 0;
        pbesLen += asn1Writer.writeInteger(iterationCount);
        pbesLen += asn1Writer.writeOctetString(salt);
        pbesLen += asn1Writer.writeSequence(pbesLen);
        // Write id-PBE OBJECT IDENTIFIER
        pbesLen += asn1Writer.writeOID(
                std::string(OID_PKCS12_PBE_SHA1_DES3_EDE_CBC, OID_SIZE(OID_PKCS12_PBE_SHA1_DES3_EDE_CBC)));
        asn1Writer.writeSequence(pbesLen);

        return asn1Writer.finish();
    }
};

}}

VirgilPBE VirgilPBE::pkcs5(const VirgilByteArray& salt, size_t iterationCount) {
    return VirgilPBE(VIRGIL_PBE_PKCS5, salt, iterationCount);
}

VirgilPBE VirgilPBE::pkcs12(const VirgilByteArray& salt, size_t iterationCount) {
    return VirgilPBE(VIRGIL_PBE_PKCS12, salt, iterationCount);
}

VirgilPBE::VirgilPBE() : impl_(new VirgilPBEImpl()) {
}

VirgilPBE::VirgilPBE(int type, const VirgilByteArray& salt, size_t iterationCount)
        : impl_(new VirgilPBEImpl(static_cast<VirgilPBEType>(type), salt, iterationCount)) {
}

VirgilPBE::~VirgilPBE() throw() {
    if (impl_) {
        delete impl_;
        impl_ = 0;
    }
}

VirgilPBE::VirgilPBE(const VirgilPBE& other) : impl_(new VirgilPBEImpl(other.impl_->algId)) {
}

VirgilPBE& VirgilPBE::operator=(const VirgilPBE& rhs) {
    if (this == &rhs) {
        return *this;
    }
    VirgilPBEImpl *newImpl = new VirgilPBEImpl(rhs.impl_->algId);
    if (impl_) {
        delete impl_;
    }
    impl_ = newImpl;
    return *this;
}

VirgilByteArray VirgilPBE::encrypt(const VirgilByteArray& data, const VirgilByteArray& pwd) const {
    int mode = (impl_->type == VIRGIL_PBE_PKCS5) ? PKCS5_ENCRYPT : PKCS12_PBE_ENCRYPT;
    return process(data, pwd, mode);
}

VirgilByteArray VirgilPBE::decrypt(const VirgilByteArray& data, const VirgilByteArray& pwd) const {
    int mode = (impl_->type == VIRGIL_PBE_PKCS5) ? PKCS5_DECRYPT : PKCS12_PBE_DECRYPT;
    return process(data, pwd, mode);
}

VirgilByteArray VirgilPBE::process(const VirgilByteArray& data, const VirgilByteArray& pwd, int mode) const {
    checkState();
    VirgilByteArray output(data.size() + POLARSSL_MAX_BLOCK_LENGTH);
    asn1_buf pbeParams = impl_->pbeParams;
    size_t olen = data.size(); // For RC4: output lenght = input length
    switch (impl_->type) {
        case VIRGIL_PBE_PKCS5:
            POLARSSL_ERROR_HANDLER(
                ::pkcs5_pbes2_ext(&pbeParams, mode,
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data),
                        output.data(), &olen)
            );
            break;
        case VIRGIL_PBE_PKCS12:
            POLARSSL_ERROR_HANDLER(
                ::pkcs12_pbe_ext(&pbeParams, mode,
                        impl_->cipherType, impl_->mdType,
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data),
                        output.data(), &olen)
            );
            break;
        case VIRGIL_PBE_PKCS12_SHA1_RC4_128:
            POLARSSL_ERROR_HANDLER(
                ::pkcs12_pbe_sha1_rc4_128(&pbeParams, mode,
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(pwd),
                        VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data),
                        output.data())
            );
            break;
        default:
            throw VirgilCryptoException("VirgilPBE: Given algorithm is not supported.");
    }
    output.resize(olen);
    return output;
}

void VirgilPBE::checkState() const {
    if (impl_->type == VIRGIL_PBE_NONE) {
        throw VirgilCryptoException(std::string("VirgilPBE: object has undefined algorithm.") +
                std::string(" Use one of the factory methods or method 'fromAsn1' to define hash algorithm."));
    }
}

size_t VirgilPBE::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    checkState();
    size_t len = asn1Writer.writeData(impl_->algId);
    return len + childWrittenBytes;
}

void VirgilPBE::asn1Read(VirgilAsn1Reader& asn1Reader) {
    if (impl_) {
        delete impl_;
    }
    impl_ = new VirgilPBEImpl(asn1Reader.readData());
}
