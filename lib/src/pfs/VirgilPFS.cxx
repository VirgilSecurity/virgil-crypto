/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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

#include <virgil/crypto/pfs/VirgilPFS.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilHash.h>

#include <cassert>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::make_error;

using virgil::crypto::primitive::VirgilOperationRandom;
using virgil::crypto::primitive::VirgilOperationHash;
using virgil::crypto::primitive::VirgilOperationCipher;
using virgil::crypto::primitive::VirgilOperationDH;
using virgil::crypto::primitive::VirgilOperationKDF;

using virgil::crypto::pfs::VirgilPFS;
using virgil::crypto::pfs::VirgilPFSSession;
using virgil::crypto::pfs::VirgilPFSPublicKey;
using virgil::crypto::pfs::VirgilPFSPrivateKey;
using virgil::crypto::pfs::VirgilPFSEncryptedMessage;
using virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo;
using virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo;
using virgil::crypto::pfs::VirgilPFSResponderPublicInfo;
using virgil::crypto::pfs::VirgilPFSResponderPrivateInfo;


static constexpr const char kAdditionalData_Virgil[] = "Virgil";
static constexpr const size_t kSaltSize = 16;
static constexpr const size_t kSecretKeySize = 128;
static constexpr const size_t kSecretKeyChunkLength = 32;
static constexpr const size_t kSecretKeyChunkNum = 4;
static constexpr const size_t kSessionIdentifierLength = 32;
static constexpr const size_t kAdditionalDataLength = 32;

VirgilPFS::VirgilPFS()
        : random_(VirgilOperationRandom::getDefault()), dh_(VirgilOperationDH::getDefault()),
          kdf_(VirgilOperationKDF::getDefault()), cipher_(VirgilOperationCipher::getDefault()), session_() {}

VirgilPFSSession VirgilPFS::startInitiatorSession(
        const VirgilPFSInitiatorPrivateInfo& initiatorPrivateInfo,
        const VirgilPFSResponderPublicInfo& responderPublicInfo, const VirgilByteArray& additionalDataMaterial) {

    auto sharedKey = calculateSharedKey(initiatorPrivateInfo, responderPublicInfo);
    auto secretKey = calculateSecretKey(sharedKey, kSecretKeySize);

    auto splittedSecretKey = bytes_split_chunks(secretKey, kSecretKeyChunkLength);
    assert(splittedSecretKey.size() == kSecretKeyChunkNum);
    auto&& encryptionSecretKey = splittedSecretKey[0];
    auto&& decryptionSecretKey = splittedSecretKey[1];
    auto&& sessionIdSecretKey = splittedSecretKey[2];
    auto&& adSecretKey = splittedSecretKey[3];

    auto additionalData = calculateAdditionalData(adSecretKey, additionalDataMaterial);
    auto identifier = calculateSessionIdentifier(sessionIdSecretKey, additionalData);

    session_ = VirgilPFSSession(
            std::move(identifier),
            std::move(encryptionSecretKey),
            std::move(decryptionSecretKey),
            std::move(additionalData));
    return session_;
}


VirgilPFSSession VirgilPFS::startResponderSession(
        const VirgilPFSResponderPrivateInfo& responderPrivateInfo,
        const VirgilPFSInitiatorPublicInfo& initiatorPublicInfo, const VirgilByteArray& additionalDataMaterial) {

    auto sharedKey = calculateSharedKey(responderPrivateInfo, initiatorPublicInfo);
    auto secretKey = calculateSecretKey(sharedKey, kSecretKeySize);

    auto splittedSecretKey = bytes_split_chunks(secretKey, kSecretKeyChunkLength);
    assert(splittedSecretKey.size() == kSecretKeyChunkNum);
    auto&& decryptionSecretKey = splittedSecretKey[0];
    auto&& encryptionSecretKey = splittedSecretKey[1];
    auto&& sessionIdSecretKey = splittedSecretKey[2];
    auto&& adSecretKey = splittedSecretKey[3];

    auto additionalData = calculateAdditionalData(adSecretKey, additionalDataMaterial);
    auto identifier = calculateSessionIdentifier(sessionIdSecretKey, additionalData);

    session_ = VirgilPFSSession(
            std::move(identifier),
            std::move(encryptionSecretKey),
            std::move(decryptionSecretKey),
            std::move(additionalData));
    return session_;
}

VirgilPFSEncryptedMessage VirgilPFS::encrypt(const VirgilByteArray& data) {

    if (session_.isEmpty()) {
        throw make_error(VirgilCryptoError::InvalidState, "PFS Session is empty, so data can not be encrypted.");
    }

    auto salt = random_.randomize(kSaltSize);

    auto keyAndNonceBytes = kdf_.derive(
            session_.getEncryptionSecretKey(), salt, str2bytes(kAdditionalData_Virgil),
            cipher_.getKeySize() + cipher_.getNonceSize());
    assert(keyAndNonceBytes.size() == cipher_.getKeySize() + cipher_.getNonceSize());

    auto keyAndNonce = bytes_split(keyAndNonceBytes, cipher_.getKeySize());
    auto key = std::move(std::get<0>(keyAndNonce));
    auto nonce = std::move(std::get<1>(keyAndNonce));
    auto cipherText = cipher_.encrypt(data, key, nonce, session_.getAdditionalData());
    return VirgilPFSEncryptedMessage(session_.getIdentifier(), std::move(salt), std::move(cipherText));
}

VirgilByteArray VirgilPFS::decrypt(const VirgilPFSEncryptedMessage& encryptedMessage) const {

    if (session_.isEmpty()) {
        throw make_error(VirgilCryptoError::InvalidState, "PFS Session is empty, so data can not be decrypted.");
    }

    auto keyAndNonceBytes = kdf_.derive(
            session_.getDecryptionSecretKey(), encryptedMessage.getSalt(), str2bytes(kAdditionalData_Virgil),
            cipher_.getKeySize() + cipher_.getNonceSize());
    assert(keyAndNonceBytes.size() == cipher_.getKeySize() + cipher_.getNonceSize());

    auto keyAndNonce = bytes_split(keyAndNonceBytes, cipher_.getKeySize());
    auto key = std::move(std::get<0>(keyAndNonce));
    auto nonce = std::move(std::get<1>(keyAndNonce));
    return cipher_.decrypt(encryptedMessage.getCipherText(), key, nonce, session_.getAdditionalData());
}

VirgilByteArray VirgilPFS::calculateAdditionalData(
        const VirgilByteArray& adSecretKey, const VirgilByteArray& additionalDataMaterial) const {

    return kdf_.derive(
            adSecretKey, additionalDataMaterial, str2bytes(kAdditionalData_Virgil), kAdditionalDataLength);
}

VirgilByteArray VirgilPFS::calculateSessionIdentifier(
        const VirgilByteArray& idSecretKey, const VirgilByteArray& additionalData) const {

    return kdf_.derive(idSecretKey, additionalData, str2bytes(kAdditionalData_Virgil), kSessionIdentifierLength);
}

VirgilByteArray VirgilPFS::calculateSharedKey(
        const VirgilPFSInitiatorPrivateInfo& initiatorPrivateInfo,
        const VirgilPFSResponderPublicInfo& responderPublicInfo) const {

    auto sharedKey = VirgilByteArray();

    bytes_append(
            sharedKey,
            dh_.calculate(
                    responderPublicInfo.getLongTermPublicKey().getKey(),
                    initiatorPrivateInfo.getIdentityPrivateKey().getKey(),
                    initiatorPrivateInfo.getIdentityPrivateKey().getPassword()));

    bytes_append(
            sharedKey,
            dh_.calculate(
                    responderPublicInfo.getIdentityPublicKey().getKey(),
                    initiatorPrivateInfo.getEphemeralPrivateKey().getKey(),
                    initiatorPrivateInfo.getEphemeralPrivateKey().getPassword()));

    bytes_append(
            sharedKey,
            dh_.calculate(
                    responderPublicInfo.getLongTermPublicKey().getKey(),
                    initiatorPrivateInfo.getEphemeralPrivateKey().getKey(),
                    initiatorPrivateInfo.getEphemeralPrivateKey().getPassword()));


    if (!responderPublicInfo.getOneTimePublicKey().isEmpty()) {
        bytes_append(
                sharedKey,
                dh_.calculate(
                        responderPublicInfo.getOneTimePublicKey().getKey(),
                        initiatorPrivateInfo.getEphemeralPrivateKey().getKey(),
                        initiatorPrivateInfo.getEphemeralPrivateKey().getPassword()));
    }

    return sharedKey;
}

VirgilByteArray VirgilPFS::calculateSharedKey(
        const VirgilPFSResponderPrivateInfo& responderPrivateInfo,
        const VirgilPFSInitiatorPublicInfo& initiatorPublicInfo) const {

    auto sharedKey = VirgilByteArray();

    bytes_append(
            sharedKey,
            dh_.calculate(
                    initiatorPublicInfo.getIdentityPublicKey().getKey(),
                    responderPrivateInfo.getLongTermPrivateKey().getKey(),
                    responderPrivateInfo.getLongTermPrivateKey().getPassword()));

    bytes_append(
            sharedKey,
            dh_.calculate(
                    initiatorPublicInfo.getEphemeralPublicKey().getKey(),
                    responderPrivateInfo.getIdentityPrivateKey().getKey(),
                    responderPrivateInfo.getIdentityPrivateKey().getPassword()));

    bytes_append(
            sharedKey,
            dh_.calculate(
                    initiatorPublicInfo.getEphemeralPublicKey().getKey(),
                    responderPrivateInfo.getLongTermPrivateKey().getKey(),
                    responderPrivateInfo.getLongTermPrivateKey().getPassword()));


    if (!responderPrivateInfo.getOneTimePrivateKey().isEmpty()) {
        bytes_append(
                sharedKey,
                dh_.calculate(
                        initiatorPublicInfo.getEphemeralPublicKey().getKey(),
                        responderPrivateInfo.getOneTimePrivateKey().getKey(),
                        responderPrivateInfo.getOneTimePrivateKey().getPassword()));
    }

    return sharedKey;
}

VirgilByteArray VirgilPFS::calculateSecretKey(const VirgilByteArray& keyMaterial, size_t size) {
    auto noSalt = VirgilByteArray();
    auto noInfo = VirgilByteArray();
    auto secretKey = kdf_.derive(keyMaterial, noSalt, noInfo, size);
    assert(secretKey.size() == size && "KDF function return size that differs from the requested.");
    return secretKey;
}

void VirgilPFS::setSession(VirgilPFSSession session) {
    session_ = std::move(session);
}

VirgilPFSSession VirgilPFS::getSession() const {
    return session_;
}

void VirgilPFS::setRandom(VirgilOperationRandom random) {
    random_ = std::move(random);
}

void VirgilPFS::setDH(VirgilOperationDH dh) {
    dh_ = std::move(dh);
}

void VirgilPFS::setKDF(VirgilOperationKDF kdf) {
    kdf_ = std::move(kdf);
}

void VirgilPFS::setCipher(VirgilOperationCipher cipher) {
    cipher_ = std::move(cipher);
}
