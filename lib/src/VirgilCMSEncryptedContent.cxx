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

#include <virgil/crypto/cms/VirgilCMSEncryptedContent.h>
using virgil::crypto::cms::VirgilCMSEncryptedContent;

#include <virgil/crypto/asn1/VirgilAsn1Reader.h>
using virgil::crypto::asn1::VirgilAsn1Reader;

#include <virgil/crypto/asn1/VirgilAsn1Writer.h>
using virgil::crypto::asn1::VirgilAsn1Writer;

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/VirgilOID.h>

#include <cstddef>
#include <string>

/**
 * @name ASN.1 Constants for CMS
 */
///@{
static const unsigned char kCMS_EncryptedContentTag = 0;
///@}

VirgilCMSEncryptedContent::~VirgilCMSEncryptedContent() throw() {
}

size_t VirgilCMSEncryptedContent::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t len = 0;
    if (!encryptedContent.empty()) {
        size_t encryptedContentLen = asn1Writer.writeOctetString(encryptedContent);
        len += encryptedContentLen;
        len += asn1Writer.writeContextTag(kCMS_EncryptedContentTag, encryptedContentLen);
    }

    checkAsn1ParamNotEmpty(contentEncryptionAlgorithm, "contentEncryptionAlgorithm");
    len += asn1Writer.writeData(contentEncryptionAlgorithm);

    len += asn1Writer.writeOID(OID_TO_STD_STRING(OID_PKCS7_DATA));
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilCMSEncryptedContent::asn1Read(VirgilAsn1Reader& asn1Reader) {
    (void)asn1Reader.readSequence();
    (void)asn1Reader.readOID(); // Ignore OID
    contentEncryptionAlgorithm = asn1Reader.readData();
    if (asn1Reader.readContextTag(kCMS_EncryptedContentTag) > 0) {
        encryptedContent = asn1Reader.readOctetString();
    }
}


