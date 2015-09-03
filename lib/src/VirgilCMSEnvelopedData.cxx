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

#include <virgil/crypto/foundation/cms/VirgilCMSEnvelopedData.h>

#include <cstddef>
#include <string>

#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/VirgilOID.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::VirgilCryptoException;
using virgil::crypto::foundation::cms::VirgilCMSEnvelopedData;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;
/**
 * @name ASN.1 Constants for CMS
 */
///@{
static const unsigned char kCMS_OriginatorInfoTag = 0;
static const unsigned char kCMS_KeyAgreeRecipientTag = 1;
static const unsigned char kCMS_KEKRecipientTag = 2;
static const unsigned char kCMS_PasswordRecipientTag = 3;
static const unsigned char kCMS_OtherRecipientTag = 4;
///@}

VirgilCMSEnvelopedData::~VirgilCMSEnvelopedData() throw() {
}

size_t VirgilCMSEnvelopedData::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t len = 0;
    // encryptedContentInfo
    len += asn1Writer.writeData(encryptedContent.toAsn1());
    // recipientInfos
    std::vector<VirgilByteArray> recipientInfos;
    recipientInfos.reserve(keyTransRecipients.size() + passwordRecipients.size());

    std::vector<VirgilCMSKeyTransRecipient>::const_iterator keyTransRecipientIt = keyTransRecipients.begin();
    for (; keyTransRecipientIt != keyTransRecipients.end(); ++keyTransRecipientIt) {
        recipientInfos.push_back(keyTransRecipientIt->toAsn1());
    }

    std::vector<VirgilCMSPasswordRecipient>::const_iterator passwordRecipientIt = passwordRecipients.begin();
    for (; passwordRecipientIt != passwordRecipients.end(); ++passwordRecipientIt) {
        VirgilAsn1Writer recipientAsn1Writer;
        size_t recipientLen = recipientAsn1Writer.writeData(passwordRecipientIt->toAsn1());
        recipientAsn1Writer.writeContextTag(kCMS_PasswordRecipientTag, recipientLen);
        recipientInfos.push_back(recipientAsn1Writer.finish());
    }

    len += asn1Writer.writeSet(recipientInfos);
    len += asn1Writer.writeInteger(defineVersion());
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilCMSEnvelopedData::asn1Read(VirgilAsn1Reader& asn1Reader) {
    keyTransRecipients.clear();
    passwordRecipients.clear();

    (void)asn1Reader.readSequence();
    (void)asn1Reader.readInteger(); // Ignore version
    if (asn1Reader.readContextTag(kCMS_OriginatorInfoTag) > 0) {
        (void)asn1Reader.readData(); // Ignore origibatorInfo
    }

    size_t setLen = asn1Reader.readSet();
    while (setLen != 0) {
        VirgilByteArray recipientAsn1 = asn1Reader.readData();
        VirgilAsn1Reader recipientAsn1Reader(recipientAsn1);

        if (recipientAsn1Reader.readContextTag(kCMS_PasswordRecipientTag) > 0) {
            VirgilCMSPasswordRecipient recipient;
            recipient.fromAsn1(recipientAsn1Reader.readData());
            passwordRecipients.push_back(recipient);
        } else {
            bool unsupportedRecipientInfoDefined =
                    recipientAsn1Reader.readContextTag(kCMS_KeyAgreeRecipientTag) > 0 ||
                    recipientAsn1Reader.readContextTag(kCMS_KEKRecipientTag) > 0 ||
                    recipientAsn1Reader.readContextTag(kCMS_OtherRecipientTag) > 0;
            if (unsupportedRecipientInfoDefined) {
                throw VirgilCryptoException(std::string("VirgilCMSEnvelopedData: ") +
                        "Given RecipientInfo type is not supported.");
            } else {
                VirgilCMSKeyTransRecipient recipient;
                recipient.fromAsn1(recipientAsn1);
                keyTransRecipients.push_back(recipient);
            }
        }
        setLen = setLen > recipientAsn1.size() ? (setLen - recipientAsn1.size()) : 0;
    }
    encryptedContent.fromAsn1(asn1Reader.readData());
}

int VirgilCMSEnvelopedData::defineVersion() const {
    if (passwordRecipients.size() > 0) {
        return 3;
    } else if (keyTransRecipients.size() > 0) {
        return 2;
    } else {
        return 0;
    }
}
