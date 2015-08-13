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

#include <virgil/crypto/foundation/cms/VirgilCMSContent.h>
using virgil::crypto::foundation::cms::VirgilCMSContent;
using virgil::crypto::foundation::cms::VirgilCMSContentType;

#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;

#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/foundation/VirgilOID.h>

#include <cstddef>
#include <cstring>
#include <string>

/**
 * @name ASN.1 Constants for CMS
 */
///@{
static const unsigned char kCMS_ContentTag = 0;
///@}

VirgilCMSContent::~VirgilCMSContent() throw() {
}

size_t VirgilCMSContent::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t len = 0;

    checkAsn1ParamNotEmpty(content, "content");
    len += asn1Writer.writeData(content);
    len += asn1Writer.writeContextTag(kCMS_ContentTag, len);
    len += asn1Writer.writeOID(contentTypeToOID(contentType));
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilCMSContent::asn1Read(VirgilAsn1Reader& asn1Reader) {
    (void)asn1Reader.readSequence();
    contentType = oidToContentType(asn1Reader.readOID());
    if (asn1Reader.readContextTag(kCMS_ContentTag) > 0) {
        content = asn1Reader.readData();
    } else {
        throw VirgilCryptoException(std::string("VirgilCMSContent: ") +
                "Expected parameter 'content' is not defined.");
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
        case VirgilCMSContentType_DigestedData:
            return OID_TO_STD_STRING(OID_PKCS7_DIGESTED_DATA);
        case VirgilCMSContentType_EncryptedData:
            return OID_TO_STD_STRING(OID_PKCS7_ENCRYPTED_DATA);
        case VirgilCMSContentType_AuthenticatedData:
            return OID_TO_STD_STRING(OID_PKCS9_AUTHENTICATED_DATA);
        default:
            throw VirgilCryptoException(std::string("VirgilCMSContent: ") +
                    "Unsupported content type was given.");
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
    } else {
        throw VirgilCryptoException(std::string("VirgilCMSContent: ") +
                "Unsupported content type OID was given.");
    }
}
