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

#include <virgil/crypto/VirgilCipherBase.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilPBE.h>
#include <virgil/crypto/foundation/cms/VirgilCMSContent.h>
#include <virgil/crypto/foundation/cms/VirgilCMSContentInfo.h>
#include <virgil/crypto/foundation/cms/VirgilCMSEnvelopedData.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/internal/utils.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCipherBase;
using virgil::crypto::VirgilCustomParams;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::make_error;


using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::VirgilSymmetricCipher;
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::VirgilPBE;
using virgil::crypto::foundation::cms::VirgilCMSContent;
using virgil::crypto::foundation::cms::VirgilCMSContentInfo;
using virgil::crypto::foundation::cms::VirgilCMSEnvelopedData;
using virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient;
using virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

namespace virgil { namespace crypto {

/**
 * @brief Handle class fields.
 */
class VirgilCipherBase::Impl {
public:
    Impl() noexcept :
            random(VirgilByteArrayUtils::stringToBytes(std::string("virgil::VirgilCipherBase"))),
            symmetricCipher(), symmetricCipherKey(), contentInfo(), envelopedData(),
            keyRecipients(), passwordRecipients() {}

public:
    VirgilRandom random;
    VirgilSymmetricCipher symmetricCipher;
    VirgilByteArray symmetricCipherKey;
    VirgilCMSContentInfo contentInfo;
    VirgilCMSEnvelopedData envelopedData;
    std::map<VirgilByteArray, VirgilByteArray> keyRecipients; ///< recipient id -> public key
    std::set<VirgilByteArray> passwordRecipients; ///< passwords
};

}}

/**
 * @name Configuration constants.
 */
///@{
static constexpr VirgilSymmetricCipher::Padding
        kSymmetricCipher_Padding = VirgilSymmetricCipher::Padding::PKCS7;
static constexpr VirgilSymmetricCipher::Algorithm
        kSymmetricCipher_Algorithm = VirgilSymmetricCipher::Algorithm::AES_256_GCM;
///@}

VirgilCipherBase::VirgilCipherBase() : impl_(std::make_unique<Impl>()) {}

VirgilCipherBase::VirgilCipherBase(VirgilCipherBase&& rhs) noexcept = default;

VirgilCipherBase& VirgilCipherBase::operator=(VirgilCipherBase&& rhs) noexcept = default;

VirgilCipherBase::~VirgilCipherBase() noexcept = default;


void VirgilCipherBase::addKeyRecipient(const VirgilByteArray& recipientId, const VirgilByteArray& publicKey) {
    if (recipientId.empty()) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    if (publicKey.empty()) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    VirgilAsymmetricCipher::checkPublicKey(publicKey);
    impl_->keyRecipients[recipientId] = publicKey;
}

void VirgilCipherBase::removeKeyRecipient(const VirgilByteArray& recipientId) {
    impl_->keyRecipients.erase(recipientId);
}

bool VirgilCipherBase::keyRecipientExists(const VirgilByteArray& recipientId) const {
    // 1. Search within local structure
    std::map<VirgilByteArray, VirgilByteArray>::const_iterator found = impl_->keyRecipients.find(recipientId);
    if (found != impl_->keyRecipients.end()) {
        return true;
    }
    // 2. Search within ContentInfo structure
    std::vector<VirgilCMSKeyTransRecipient>::const_iterator recipientIt =
            impl_->envelopedData.keyTransRecipients.begin();
    for (; recipientIt != impl_->envelopedData.keyTransRecipients.end(); ++recipientIt) {
        if (recipientIt->recipientIdentifier == recipientId) {
            return true;
        }
    }
    // 3. Not found within any structure
    return false;
}

void VirgilCipherBase::addPasswordRecipient(const VirgilByteArray& pwd) {
    if (pwd.empty()) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    impl_->passwordRecipients.insert(pwd);
}

void VirgilCipherBase::removePasswordRecipient(const VirgilByteArray& pwd) {
    impl_->passwordRecipients.erase(pwd);
}

bool VirgilCipherBase::passwordRecipientExists(const VirgilByteArray& password) const {
    // Search within local structure only
    return impl_->passwordRecipients.find(password) != impl_->passwordRecipients.end();
}

void VirgilCipherBase::removeAllRecipients() {
    impl_->keyRecipients.clear();
    impl_->passwordRecipients.clear();
}

VirgilByteArray VirgilCipherBase::getContentInfo() const {
    return impl_->contentInfo.toAsn1();
}

void VirgilCipherBase::setContentInfo(const VirgilByteArray& contentInfo) {
    impl_->contentInfo.fromAsn1(contentInfo);
    if (impl_->contentInfo.cmsContent.contentType == foundation::cms::VirgilCMSContent::Type::EnvelopedData) {
        impl_->envelopedData.fromAsn1(impl_->contentInfo.cmsContent.content);
    } else {
        throw make_error(VirgilCryptoError::InvalidFormat);
    }
}

size_t VirgilCipherBase::defineContentInfoSize(const VirgilByteArray& data) {
    return VirgilCMSContentInfo::defineSize(data);
}

VirgilCustomParams& VirgilCipherBase::customParams() {
    return impl_->contentInfo.customParams;
}

const VirgilCustomParams& VirgilCipherBase::customParams() const {
    return impl_->contentInfo.customParams;
}

VirgilByteArray VirgilCipherBase::computeShared(
        const VirgilByteArray& publicKey, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    VirgilAsymmetricCipher publicContext;
    VirgilAsymmetricCipher privateContext;
    publicContext.setPublicKey(publicKey);
    privateContext.setPrivateKey(privateKey, privateKeyPassword);
    return VirgilAsymmetricCipher::computeShared(publicContext, privateContext);
}

VirgilByteArray VirgilCipherBase::tryReadContentInfo(const VirgilByteArray& encryptedData) {
    size_t contentInfoSize = defineContentInfoSize(encryptedData);
    if (contentInfoSize > 0) {
        VirgilByteArray contentInfo(encryptedData.begin(), encryptedData.begin() + contentInfoSize);
        VirgilByteArray payload(encryptedData.begin() + contentInfoSize, encryptedData.end());
        setContentInfo(contentInfo);
        return payload;
    }
    return encryptedData;
}

VirgilSymmetricCipher& VirgilCipherBase::initEncryption() {
    impl_->symmetricCipher = VirgilSymmetricCipher(kSymmetricCipher_Algorithm);
    impl_->symmetricCipherKey = impl_->random.randomize(impl_->symmetricCipher.keyLength());
    VirgilByteArray symmetricCipherIV = impl_->random.randomize(impl_->symmetricCipher.ivSize());
    impl_->symmetricCipher.setEncryptionKey(impl_->symmetricCipherKey);
    impl_->symmetricCipher.setIV(symmetricCipherIV);
    if (impl_->symmetricCipher.isSupportPadding()) {
        impl_->symmetricCipher.setPadding(kSymmetricCipher_Padding);
    }
    impl_->symmetricCipher.reset();

    return impl_->symmetricCipher;
}

static VirgilByteArray decryptContentEncryptionKey(
        const std::vector<VirgilCMSPasswordRecipient>& passwordRecipients, const VirgilByteArray& pwd) {
    VirgilPBE pbe;
    std::vector<VirgilCMSPasswordRecipient>::const_iterator recipientIt = passwordRecipients.begin();
    for (; recipientIt != passwordRecipients.end(); ++recipientIt) {
        try {
            pbe.fromAsn1(recipientIt->keyEncryptionAlgorithm);
            return pbe.decrypt(recipientIt->encryptedKey, pwd);
        } catch (...) {
            // Possible wrong password, so try next one.
        }
    }
    throw make_error(VirgilCryptoError::NotFoundPasswordRecipient);
}

static VirgilByteArray decryptContentEncryptionKey(
        const std::vector<VirgilCMSKeyTransRecipient>& keyTransRecipients, const VirgilByteArray& recipientId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword = VirgilByteArray()) {
    std::vector<VirgilCMSKeyTransRecipient>::const_iterator recipientIt = keyTransRecipients.begin();
    for (; recipientIt != keyTransRecipients.end(); ++recipientIt) {
        if (recipientIt->recipientIdentifier == recipientId) {
            VirgilAsymmetricCipher asymmetricCipher;
            asymmetricCipher.setPrivateKey(privateKey, privateKeyPassword);
            return asymmetricCipher.decrypt(recipientIt->encryptedKey);
        }
    }
    throw make_error(VirgilCryptoError::NotFoundKeyRecipient);
}

VirgilSymmetricCipher& VirgilCipherBase::initDecryptionWithPassword(const VirgilByteArray& pwd) {
    VirgilByteArray contentEncryptionKey =
            decryptContentEncryptionKey(impl_->envelopedData.passwordRecipients, pwd);
    impl_->symmetricCipher = VirgilSymmetricCipher();
    impl_->symmetricCipher.fromAsn1(impl_->envelopedData.encryptedContent.contentEncryptionAlgorithm);
    impl_->symmetricCipher.setDecryptionKey(contentEncryptionKey);
    if (impl_->symmetricCipher.isSupportPadding()) {
        impl_->symmetricCipher.setPadding(kSymmetricCipher_Padding);
    }
    impl_->symmetricCipher.reset();
    return impl_->symmetricCipher;
}

VirgilSymmetricCipher& VirgilCipherBase::initDecryptionWithKey(
        const VirgilByteArray& recipientId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {

    VirgilByteArray contentEncryptionKey =
            decryptContentEncryptionKey(impl_->envelopedData.keyTransRecipients, recipientId, privateKey,
                    privateKeyPassword);
    impl_->symmetricCipher = VirgilSymmetricCipher();
    impl_->symmetricCipher.fromAsn1(impl_->envelopedData.encryptedContent.contentEncryptionAlgorithm);
    impl_->symmetricCipher.setDecryptionKey(contentEncryptionKey);
    if (impl_->symmetricCipher.isSupportPadding()) {
        impl_->symmetricCipher.setPadding(kSymmetricCipher_Padding);
    }
    impl_->symmetricCipher.reset();
    return impl_->symmetricCipher;
}

void VirgilCipherBase::buildContentInfo() {
    // Remove stale recipients.
    impl_->envelopedData.keyTransRecipients.clear();
    impl_->envelopedData.passwordRecipients.clear();
    // Add KeyTransRecipient's
    for (std::map<VirgilByteArray, VirgilByteArray>::const_iterator it = impl_->keyRecipients.begin();
         it != impl_->keyRecipients.end(); ++it) {
        const VirgilByteArray& recipientId = it->first;
        const VirgilByteArray& publicKey = it->second;

        VirgilAsymmetricCipher asymmetricCipher;
        asymmetricCipher.setPublicKey(publicKey);

        VirgilCMSKeyTransRecipient recipient;
        recipient.recipientIdentifier = recipientId;
        recipient.encryptedKey = asymmetricCipher.encrypt(impl_->symmetricCipherKey);
        recipient.keyEncryptionAlgorithm = asymmetricCipher.toAsn1();

        impl_->envelopedData.keyTransRecipients.push_back(recipient);
    }
    // Add PasswordRecipient's
    for (std::set<VirgilByteArray>::const_iterator it = impl_->passwordRecipients.begin();
         it != impl_->passwordRecipients.end(); ++it) {
        const VirgilByteArray& password = *it;

        const VirgilByteArray salt = impl_->random.randomize(16);
        const size_t iterationCount = impl_->random.randomize(3072, 8192);

        VirgilPBE pbe(VirgilPBE::Algorithm::PKCS5, salt, iterationCount);

        VirgilCMSPasswordRecipient recipient;
        recipient.keyEncryptionAlgorithm = pbe.toAsn1();
        recipient.encryptedKey = pbe.encrypt(impl_->symmetricCipherKey, password);
        impl_->envelopedData.passwordRecipients.push_back(recipient);
    }
    // Add information about content encryption algorithm.
    impl_->envelopedData.encryptedContent.contentEncryptionAlgorithm = impl_->symmetricCipher.toAsn1();
    impl_->envelopedData.encryptedContent.encryptedContent.clear();
    // Define content info
    impl_->contentInfo.cmsContent.contentType = foundation::cms::VirgilCMSContent::Type::EnvelopedData;
    impl_->contentInfo.cmsContent.content = impl_->envelopedData.toAsn1();
}

void VirgilCipherBase::clearCipherInfo() {
    impl_->symmetricCipher.clear();
    VirgilByteArrayUtils::zeroize(impl_->symmetricCipherKey);
}

VirgilSymmetricCipher& VirgilCipherBase::getSymmetricCipher() {
    return impl_->symmetricCipher;
}
