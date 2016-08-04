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

#define MODULE_NAME "VirgilCMSContent"

#include <virgil/crypto/foundation/cms/VirgilCMSContent.h>

#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/internal/VirgilOID.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/internal/utils.h>

using virgil::crypto::foundation::cms::VirgilCMSContent;
using virgil::crypto::foundation::cms::VirgilCMSContentType;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

/**
 * @name ASN.1 Constants for CMS
 */
///@{
static const unsigned char kCMS_ContentTag = 0;
///@}

VirgilCMSContent::~VirgilCMSContent() noexcept {
}

size_t VirgilCMSContent::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t len = 0;

    checkRequiredField(content);
    len += asn1Writer.writeData(content);
    len += asn1Writer.writeContextTag(kCMS_ContentTag, len);
    len += asn1Writer.writeOID(contentTypeToOID(contentType));
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilCMSContent::asn1Read(VirgilAsn1Reader& asn1Reader) {
    (void) asn1Reader.readSequence();
    contentType = oidToContentType(asn1Reader.readOID());
    if (asn1Reader.readContextTag(kCMS_ContentTag) > 0) {
        content = asn1Reader.readData();
    } else {
        throw make_error(VirgilCryptoError::InvalidFormat);
    }
}

std::string VirgilCMSContent::contentTypeToOID(VirgilCMSContentType contentType) {
    switch (contentType) {
        case VirgilCMSContentType_Data:
            return OID_TO_STD_STRING(OID_PKCS7_DATA);
        case VirgilCMSContentType_SignedData:
            return OID_TO_STD_STRING(OID_PKCS7_SIGNED_DATA);
        case VirgilCMSContentType_EnvelopedData:
            return OID_TO_STD_STRING(OID_PKCS7_ENVELOPED_DATA);
        case VirgilCMSContentType_SignedAndEnvelopedData:
            return OID_TO_STD_STRING(OID_PKCS7_SIGNED_AND_ENVELOPED_DATA);
        case VirgilCMSContentType_DigestedData:
            return OID_TO_STD_STRING(OID_PKCS7_DIGESTED_DATA);
        case VirgilCMSContentType_EncryptedData:
            return OID_TO_STD_STRING(OID_PKCS7_ENCRYPTED_DATA);
        case VirgilCMSContentType_DataWithAttributes:
            return OID_TO_STD_STRING(OID_PKCS7_DATA_WITH_ATTRIBUTES);
        case VirgilCMSContentType_EncryptedPrivateKeyInfo:
            return OID_TO_STD_STRING(OID_PKCS7_ENCRYPTED_PRIVATE_KEY_INFO);
        case VirgilCMSContentType_AuthenticatedData:
            return OID_TO_STD_STRING(OID_PKCS9_AUTHENTICATED_DATA);
        default:
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}

VirgilCMSContentType VirgilCMSContent::oidToContentType(const std::string& oid) {
    if (compareOID(OID_TO_STD_STRING(OID_PKCS7_DATA), oid)) {
        return VirgilCMSContentType_Data;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS7_SIGNED_DATA), oid)) {
        return VirgilCMSContentType_SignedData;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS7_ENVELOPED_DATA), oid)) {
        return VirgilCMSContentType_EnvelopedData;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS7_DIGESTED_DATA), oid)) {
        return VirgilCMSContentType_DigestedData;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS7_ENCRYPTED_DATA), oid)) {
        return VirgilCMSContentType_EncryptedData;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS9_AUTHENTICATED_DATA), oid)) {
        return VirgilCMSContentType_AuthenticatedData;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS7_SIGNED_AND_ENVELOPED_DATA), oid)) {
        return VirgilCMSContentType_SignedAndEnvelopedData;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS7_DATA_WITH_ATTRIBUTES), oid)) {
        return VirgilCMSContentType_DataWithAttributes;
    } else if (compareOID(OID_TO_STD_STRING(OID_PKCS7_ENCRYPTED_PRIVATE_KEY_INFO), oid)) {
        return VirgilCMSContentType_EncryptedPrivateKeyInfo;
    } else {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}
