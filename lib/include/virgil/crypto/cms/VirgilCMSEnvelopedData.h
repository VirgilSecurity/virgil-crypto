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

#ifndef VIRGIL_CRYPTO_CMS_VIRGIL_CMS_ENVELOPED_DATA_H
#define VIRGIL_CRYPTO_CMS_VIRGIL_CMS_ENVELOPED_DATA_H

#include <virgil/crypto/VirgilAsn1Compatible.h>
using virgil::crypto::VirgilAsn1Compatible;

#include <virgil/crypto/cms/VirgilCMSKeyTransRecipient.h>
using virgil::crypto::cms::VirgilCMSKeyTransRecipient;

#include <virgil/crypto/cms/VirgilCMSPasswordRecipient.h>
using virgil::crypto::cms::VirgilCMSPasswordRecipient;

#include <virgil/crypto/cms/VirgilCMSEncryptedContent.h>
using virgil::crypto::cms::VirgilCMSEncryptedContent;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <vector>

namespace virgil { namespace crypto { namespace cms {

/**
 * @brief Data object that represent CMS structure: EnvelopedData.
 * @see RFC 5652 section 6.1.
 */
class VirgilCMSEnvelopedData : public VirgilAsn1Compatible {
public:
    std::vector<VirgilCMSKeyTransRecipient> keyTransRecipients;
    std::vector<VirgilCMSPasswordRecipient> passwordRecipients;
    VirgilCMSEncryptedContent encryptedContent;
public:
    /**
     * @name VirgilAsn1Compatible implementation
     *
     * Marshalling format:
     *     EnvelopedData ::= SEQUENCE {
     *         version CMSVersion,
     *         originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
     *         recipientInfos RecipientInfos,
     *         encryptedContentInfo EncryptedContentInfo,
     *         unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
     *     }
     *
     *     CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
     *
     *     OriginatorInfo ::= SEQUENCE {
     *         certs [0] IMPLICIT CertificateSet OPTIONAL,
     *         crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
     *     }
     *
     *     RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
     *
     *     EncryptedContentInfo ::= SEQUENCE {...}
     *
     *     RecipientInfo ::= CHOICE {
     *         ktri KeyTransRecipientInfo,
     *         kari [1] KeyAgreeRecipientInfo, -- not supported
     *         kekri [2] KEKRecipientInfo, -- not supported
     *         pwri [3] PasswordRecipientInfo,
     *         ori [4] OtherRecipientInfo -- not supported
     *     }
     */
    ///@{
    virtual VirgilByteArray toAsn1() const;
    virtual void fromAsn1(const VirgilByteArray& asn1);
    ///@}
public:
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilCMSEnvelopedData() throw();
private:
    int defineVersion() const;
};

}}}

#endif /* VIRGIL_CRYPTO_CMS_VIRGIL_CMS_ENVELOPED_DATA_H */
