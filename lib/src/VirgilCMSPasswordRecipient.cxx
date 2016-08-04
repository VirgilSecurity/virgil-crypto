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

#include <virgil/crypto/foundation/cms/VirgilCMSPasswordRecipient.h>

#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/internal/utils.h>

using virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

/**
 * @name ASN.1 Constants for CMS
 */
///@{
static const unsigned char kCMS_KeyDerivationAlgorithmTag = 0;
static const int kCMS_PasswordRecipientVersion = 0;
///@}

VirgilCMSPasswordRecipient::~VirgilCMSPasswordRecipient() noexcept {
}

size_t VirgilCMSPasswordRecipient::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t len = 0;

    checkRequiredField(encryptedKey);
    len += asn1Writer.writeOctetString(encryptedKey);

    checkRequiredField(keyEncryptionAlgorithm);
    len += asn1Writer.writeData(keyEncryptionAlgorithm);

    if (!keyDerivationAlgorithm.empty()) {
        size_t keyDerivationAlgorithmLen = asn1Writer.writeOctetString(keyDerivationAlgorithm);
        len += keyDerivationAlgorithmLen;
        len += asn1Writer.writeContextTag(kCMS_KeyDerivationAlgorithmTag, keyDerivationAlgorithmLen);
    }

    len += asn1Writer.writeInteger(kCMS_PasswordRecipientVersion);
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilCMSPasswordRecipient::asn1Read(VirgilAsn1Reader& asn1Reader) {
    (void) asn1Reader.readSequence();
    int version = asn1Reader.readInteger();
    if (version != kCMS_PasswordRecipientVersion) {
        throw make_error(VirgilCryptoError::InvalidFormat,
                "PasswordRecipientInfo structure is malformed due to incorrect CMS version number.");
    }

    if (asn1Reader.readContextTag(kCMS_KeyDerivationAlgorithmTag) > 0) {
        keyDerivationAlgorithm = asn1Reader.readData();
    }
    keyEncryptionAlgorithm = asn1Reader.readData();
    encryptedKey = asn1Reader.readOctetString();
}


