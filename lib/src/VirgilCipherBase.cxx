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

#include <virgil/service/VirgilCipherBase.h>
using virgil::service::VirgilCipherBase;

#include <cstring>
#include <string>
using std::string;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <virgil/crypto/VirgilRandom.h>
using virgil::crypto::VirgilRandom;

#include <virgil/crypto/VirgilSymmetricCipher.h>
using virgil::crypto::VirgilSymmetricCipher;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

#include <virgil/crypto/VirgilPBE.h>
using virgil::crypto::VirgilPBE;

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/cms/VirgilCMSContent.h>
using virgil::crypto::cms::VirgilCMSContent;

#include <virgil/crypto/cms/VirgilCMSKeyTransRecipient.h>
using virgil::crypto::cms::VirgilCMSKeyTransRecipient;

#include <virgil/crypto/cms/VirgilCMSPasswordRecipient.h>
using virgil::crypto::cms::VirgilCMSPasswordRecipient;

/**
 * @name Configuration constants.
 */
///@{
static const VirgilSymmetricCipher::VirgilSymmetricCipherPadding kSymmetricCipher_Padding =
        VirgilSymmetricCipher::VirgilSymmetricCipherPadding_PKCS7;
///@}

VirgilCipherBase::VirgilCipherBase()
        : random_(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(std::string("virgil::service::VirgilCipherBase"))),
        symmetricCipher_(), symmetricCipherKey_(), contentInfo_(), envelopedData_(),
        keyRecipients_(), passwordRecipients_() {
}

VirgilCipherBase::~VirgilCipherBase() throw() {
}

void VirgilCipherBase::addKeyRecipient(const VirgilByteArray& certificateId, const VirgilByteArray& publicKey) {
    if (certificateId.empty() || publicKey.empty()) {
        throw VirgilException("VirgilCipherBase: Parameters 'certificateId' or 'publicKey' are not specified.");
    }
    keyRecipients_[certificateId] = publicKey;
}

void VirgilCipherBase::removeKeyRecipient(const VirgilByteArray& certificateId) {
    keyRecipients_.erase(certificateId);
}

void VirgilCipherBase::addPasswordRecipient(const VirgilByteArray& pwd) {
    if (pwd.empty()) {
        throw VirgilException("VirgilCipherBase: Parameter 'pwd' is not specified.");
    }
    passwordRecipients_.insert(pwd);
}

void VirgilCipherBase::removePasswordRecipient(const VirgilByteArray& pwd) {
    passwordRecipients_.erase(pwd);
}

void VirgilCipherBase::removeAllRecipients() {
    keyRecipients_.clear();
    passwordRecipients_.clear();
}

VirgilByteArray VirgilCipherBase::getContentInfo() const {
    return contentInfo_.toAsn1();
}

void VirgilCipherBase::setContentInfo(const VirgilByteArray& contentInfo) {
    contentInfo_.fromAsn1(contentInfo);
    if (contentInfo_.cmsContent.contentType == crypto::cms::VirgilCMSContentType_EnvelopedData) {
        envelopedData_.fromAsn1(contentInfo_.cmsContent.content);
    } else {
        throw VirgilException("VirgilCipherBase: Unsupported content info type was given.");
    }
}

VirgilCustomParams& VirgilCipherBase::customParameters() {
    return contentInfo_.customParams;
}

const VirgilCustomParams& VirgilCipherBase::customParameters() const {
    return contentInfo_.customParams;
}

VirgilSymmetricCipher& VirgilCipherBase::initEncryption() {
    symmetricCipher_ = VirgilSymmetricCipher::aes256();
    symmetricCipherKey_ = random_.randomize(symmetricCipher_.keyLength());
    VirgilByteArray symmetricCipherIV = random_.randomize(symmetricCipher_.ivSize());
    symmetricCipher_.setEncryptionKey(symmetricCipherKey_);
    symmetricCipher_.setIV(symmetricCipherIV);
    symmetricCipher_.setPadding(kSymmetricCipher_Padding);
    symmetricCipher_.reset();

    return symmetricCipher_;
}

static VirgilByteArray decryptContentEncryptionKey(
        const std::vector<VirgilCMSPasswordRecipient>& passwordRecipients, const VirgilByteArray& pwd) {
    VirgilPBE pbe;
    std::vector<VirgilCMSPasswordRecipient>::const_iterator recipientIt = passwordRecipients.begin();
    for (; recipientIt != passwordRecipients.end(); ++recipientIt) {
        try {
            pbe.fromAsn1(recipientIt->keyEncryptionAlgorithm);
            return pbe.decrypt(recipientIt->encryptedKey, pwd);
        } catch (const VirgilCryptoException&) {
            // Possible wrong password, so try next one.
        }
    }
    throw VirgilException("VirgilCipherBase: Recipient with given password not found.");
}

static VirgilByteArray decryptContentEncryptionKey(
        const std::vector<VirgilCMSKeyTransRecipient>& keyTransRecipients, const VirgilByteArray& certificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword = VirgilByteArray()) {
    std::vector<VirgilCMSKeyTransRecipient>::const_iterator recipientIt = keyTransRecipients.begin();
    for (; recipientIt != keyTransRecipients.end(); ++recipientIt) {
        if (recipientIt->recipientIdentifier == certificateId) {
            VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
            asymmetricCipher.setPrivateKey(privateKey, privateKeyPassword);
            return asymmetricCipher.decrypt(recipientIt->encryptedKey);
        }
    }
    throw VirgilException(std::string("VirgilCipherBase: ") + "Recipient with given certificate id (" +
            VIRGIL_BYTE_ARRAY_TO_STD_STRING(certificateId) + ") is not found.");
}

VirgilSymmetricCipher& VirgilCipherBase::initDecryptionWithPassword(const VirgilByteArray& pwd) {
    VirgilByteArray contentEncryptionKey =
            decryptContentEncryptionKey(envelopedData_.passwordRecipients, pwd);
    symmetricCipher_ = VirgilSymmetricCipher();
    symmetricCipher_.fromAsn1(envelopedData_.encryptedContent.contentEncryptionAlgorithm);
    symmetricCipher_.setDecryptionKey(contentEncryptionKey);
    symmetricCipher_.setPadding(kSymmetricCipher_Padding);
    symmetricCipher_.reset();
    return symmetricCipher_;
}

VirgilSymmetricCipher& VirgilCipherBase::initDecryptionWithKey(const VirgilByteArray& certificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {

    VirgilByteArray contentEncryptionKey =
            decryptContentEncryptionKey(envelopedData_.keyTransRecipients, certificateId, privateKey, privateKeyPassword);
    symmetricCipher_ = VirgilSymmetricCipher();
    symmetricCipher_.fromAsn1(envelopedData_.encryptedContent.contentEncryptionAlgorithm);
    symmetricCipher_.setDecryptionKey(contentEncryptionKey);
    symmetricCipher_.setPadding(kSymmetricCipher_Padding);
    symmetricCipher_.reset();
    return symmetricCipher_;
}

void VirgilCipherBase::buildContentInfo() {
    // Remove stale recipients.
    envelopedData_.keyTransRecipients.clear();
    envelopedData_.passwordRecipients.clear();
    // Add KeyTransRecipient's
    for (KeyRecipientsType::const_iterator it = keyRecipients_.begin();
            it != keyRecipients_.end(); ++it) {
        const VirgilByteArray& certificateId = it->first;
        const VirgilByteArray& publicKey = it->second;

        VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
        asymmetricCipher.setPublicKey(publicKey);

        VirgilCMSKeyTransRecipient recipient;
        recipient.recipientIdentifier = certificateId;
        recipient.encryptedKey = asymmetricCipher.encrypt(symmetricCipherKey_);
        recipient.keyEncryptionAlgorithm = asymmetricCipher.toAsn1();

        envelopedData_.keyTransRecipients.push_back(recipient);
    }
    // Add PasswordRecipient's
    for (PasswordRecipientsType::const_iterator it = passwordRecipients_.begin();
            it != passwordRecipients_.end(); ++it) {
        const VirgilByteArray& password = *it;

        const VirgilByteArray salt = random_.randomize(16);
        const size_t iterationCount = 2048;

        VirgilPBE pbe = VirgilPBE::pkcs12(salt, iterationCount);

        VirgilCMSPasswordRecipient recipient;
        recipient.keyEncryptionAlgorithm = pbe.toAsn1();
        recipient.encryptedKey = pbe.encrypt(symmetricCipherKey_, password);
        envelopedData_.passwordRecipients.push_back(recipient);
    }
    // Add information about content encryption algorithm.
    envelopedData_.encryptedContent.contentEncryptionAlgorithm = symmetricCipher_.toAsn1();
    envelopedData_.encryptedContent.encryptedContent.clear();
    // Define content info
    contentInfo_.cmsContent.contentType = crypto::cms::VirgilCMSContentType_EnvelopedData;
    contentInfo_.cmsContent.content = envelopedData_.toAsn1();
}

void VirgilCipherBase::clearCipherInfo() {
    symmetricCipher_.clear();
    VIRGIL_BYTE_ARRAY_ZEROIZE(symmetricCipherKey_);
}

VirgilSymmetricCipher& VirgilCipherBase::getSymmetricCipher() {
    return symmetricCipher_;
}
