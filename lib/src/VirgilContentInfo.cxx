/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <virgil/crypto/VirgilContentInfo.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/cms/VirgilCMSContent.h>
#include <virgil/crypto/foundation/cms/VirgilCMSContentInfo.h>
#include <virgil/crypto/foundation/cms/VirgilCMSEnvelopedData.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include "utils.h"

#include <algorithm>
#include <set>


using virgil::crypto::VirgilContentInfo;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCustomParams;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::make_error;

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
class VirgilContentInfo::Impl {
public:
    VirgilCMSContentInfo cmsContentInfo;
    VirgilCMSEnvelopedData cmsEnvelopedData;
    std::map<VirgilByteArray, VirgilByteArray> keyRecipients; ///< recipient id -> public key
    std::set<VirgilByteArray> passwordRecipients; ///< passwords
};

}}

VirgilContentInfo::VirgilContentInfo() : impl_(std::make_unique<VirgilContentInfo::Impl>()) {}

VirgilContentInfo::VirgilContentInfo(VirgilContentInfo&& rhs) noexcept = default;

VirgilContentInfo& VirgilContentInfo::operator=(VirgilContentInfo&& rhs) noexcept = default;

VirgilContentInfo::~VirgilContentInfo() noexcept = default;

void VirgilContentInfo::addKeyRecipient(const VirgilByteArray& recipientId, const VirgilByteArray& publicKey) {
    if (recipientId.empty()) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    if (publicKey.empty()) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    if (hasKeyRecipient(recipientId)) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    impl_->keyRecipients[recipientId] = publicKey;
}

bool VirgilContentInfo::hasKeyRecipient(const VirgilByteArray& recipientId) const {
    // 1. Search within RAW representation
    if (impl_->keyRecipients.find(recipientId) != impl_->keyRecipients.end()) {
        return true;
    }
    // 2. Search within CMS representation
    return std::find_if(
            impl_->cmsEnvelopedData.keyTransRecipients.cbegin(),
            impl_->cmsEnvelopedData.keyTransRecipients.cend(),
            [&recipientId](const VirgilCMSKeyTransRecipient& keyTransRecipient) {
                return keyTransRecipient.recipientIdentifier == recipientId;
            }
    ) != impl_->cmsEnvelopedData.keyTransRecipients.cend();
}

void VirgilContentInfo::removeKeyRecipient(const VirgilByteArray& recipientId) {
    // Remove from the RAW representation
    impl_->keyRecipients.erase(recipientId);
    // Remove from the CMS representation
    auto found = std::find_if(
            // Use non const iterators, it's cause an error for vector::erase() in gcc 4.8.5
            impl_->cmsEnvelopedData.keyTransRecipients.begin(),
            impl_->cmsEnvelopedData.keyTransRecipients.end(),
            [&recipientId](const VirgilCMSKeyTransRecipient& recipient) {
                return recipient.recipientIdentifier == recipientId;
            }
    );
    if (found != impl_->cmsEnvelopedData.keyTransRecipients.end()) {
        impl_->cmsEnvelopedData.keyTransRecipients.erase(found);
    }
}

void VirgilContentInfo::removeKeyRecipients() {
    // Remove from the RAW representation
    impl_->keyRecipients.clear();
    // Remove from the CMS representation
    impl_->cmsEnvelopedData.keyTransRecipients.clear();
}

void VirgilContentInfo::addPasswordRecipient(const VirgilByteArray& pwd) {
    if (pwd.empty()) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    impl_->passwordRecipients.insert(pwd);
}

bool VirgilContentInfo::hasPasswordRecipient(const VirgilByteArray& password) const {
    // Search within local structure only
    return impl_->passwordRecipients.find(password) != impl_->passwordRecipients.end();
}

void VirgilContentInfo::removePasswordRecipient(const VirgilByteArray& pwd) {
    // Remove from the RAW representation
    impl_->passwordRecipients.erase(pwd);
    // Remove from the CMS representation
    // INFO: It's impossible
}

void VirgilContentInfo::removePasswordRecipients() {
    // Remove from the RAW representation
    impl_->passwordRecipients.clear();
    // Remove from the CMS representation
    impl_->cmsEnvelopedData.passwordRecipients.clear();
}

void VirgilContentInfo::removeAllRecipients() {
    removeKeyRecipients();
    removePasswordRecipients();
}

VirgilCustomParams& VirgilContentInfo::customParams() {
    return impl_->cmsContentInfo.customParams;
}

const VirgilCustomParams& VirgilContentInfo::customParams() const {
    return impl_->cmsContentInfo.customParams;
}

VirgilByteArray VirgilContentInfo::decryptKeyRecipient(const VirgilByteArray& recipientId,
        std::function<VirgilByteArray(const VirgilByteArray&, const VirgilByteArray&)> decrypt) const {

    if (!decrypt) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    for (const auto& keyRecipient: impl_->cmsEnvelopedData.keyTransRecipients) {
        if (keyRecipient.recipientIdentifier == recipientId) {
            return decrypt(keyRecipient.keyEncryptionAlgorithm, keyRecipient.encryptedKey);
        }
    }
    return VirgilByteArray();
}

VirgilByteArray VirgilContentInfo::decryptPasswordRecipient(
        std::function<VirgilByteArray(const VirgilByteArray&, const VirgilByteArray&)> decrypt) const {
    if (!decrypt) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    for (const auto& passwordRecipient: impl_->cmsEnvelopedData.passwordRecipients) {
        try {
            return decrypt(passwordRecipient.keyEncryptionAlgorithm, passwordRecipient.encryptedKey);
        } catch (...) {
            // Possible wrong password, so try next one.
        }
    }
    return VirgilByteArray();
}

void VirgilContentInfo::encryptKeyRecipients(std::function<EncryptionResult(const VirgilByteArray&)> encrypt) {
    if (!encrypt) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    for (const auto& keyRecipient : impl_->keyRecipients) {
        const auto& recipientId = keyRecipient.first;
        const auto& publicKey = keyRecipient.second;

        auto encryptionResult = encrypt(publicKey);

        VirgilCMSKeyTransRecipient recipient;
        recipient.recipientIdentifier = recipientId;
        recipient.keyEncryptionAlgorithm = encryptionResult.encryptionAlgorithm;
        recipient.encryptedKey = encryptionResult.encryptedContent;

        impl_->cmsEnvelopedData.keyTransRecipients.push_back(recipient);
    }
    impl_->keyRecipients.clear();
}

void VirgilContentInfo::encryptPasswordRecipients(std::function<EncryptionResult(const VirgilByteArray&)> encrypt) {
    if (!encrypt) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    for (const auto& password : impl_->passwordRecipients) {
        auto encryptionResult = encrypt(password);

        VirgilCMSPasswordRecipient recipient;
        recipient.keyEncryptionAlgorithm = encryptionResult.encryptionAlgorithm;
        recipient.encryptedKey = encryptionResult.encryptedContent;

        impl_->cmsEnvelopedData.passwordRecipients.push_back(recipient);
    }
    impl_->passwordRecipients.clear();
}

void VirgilContentInfo::setContentEncryptionAlgorithm(const VirgilByteArray& contentEncryptionAlgorithm) {
    impl_->cmsEnvelopedData.encryptedContent.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
}

VirgilByteArray VirgilContentInfo::getContentEncryptionAlgorithm() const {
    return impl_->cmsEnvelopedData.encryptedContent.contentEncryptionAlgorithm;
}

size_t VirgilContentInfo::defineSize(const VirgilByteArray& contentInfoData) {
    return VirgilCMSContentInfo::defineSize(contentInfoData);
}

size_t VirgilContentInfo::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    impl_->cmsContentInfo.cmsContent.contentType = VirgilCMSContent::Type::EnvelopedData;
    impl_->cmsContentInfo.cmsContent.content = impl_->cmsEnvelopedData.toAsn1();
    return impl_->cmsContentInfo.asn1Write(asn1Writer, childWrittenBytes);
}

void VirgilContentInfo::asn1Read(VirgilAsn1Reader& asn1Reader) {
    impl_->cmsContentInfo.asn1Read(asn1Reader);
    if (impl_->cmsContentInfo.cmsContent.contentType == foundation::cms::VirgilCMSContent::Type::EnvelopedData) {
        impl_->cmsEnvelopedData.fromAsn1(impl_->cmsContentInfo.cmsContent.content);
    } else {
        throw make_error(VirgilCryptoError::InvalidFormat);
    }
}
