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

#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::VirgilAsymmetricCipher;

VirgilKeyPair VirgilKeyPair::generate(VirgilKeyPair::Type type, const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher;
    cipher.genKeyPair(type);
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::generateRecommended(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher;
    cipher.genKeyPair(Type::EC_ED25519);
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::generateFrom(
        const VirgilKeyPair& donorKeyPair, const VirgilByteArray& donorPrivateKeyPassword,
        const VirgilByteArray& newKeyPairPassword) {

    VirgilAsymmetricCipher donorCipher;
    if (!donorKeyPair.publicKey_.empty()) {
        donorCipher.setPublicKey(donorKeyPair.publicKey_);
    } else if (!donorKeyPair.privateKey_.empty()) {
        donorCipher.setPrivateKey(donorKeyPair.privateKey_, donorPrivateKeyPassword);
    }

    VirgilAsymmetricCipher cipher;
    cipher.genKeyPairFrom(donorCipher);
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(newKeyPairPassword));
}

bool VirgilKeyPair::isKeyPairMatch(
        const VirgilByteArray& publicKey, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {
    return VirgilAsymmetricCipher::isKeyPairMatch(publicKey, privateKey, privateKeyPassword);
}

bool VirgilKeyPair::checkPrivateKeyPassword(
        const VirgilByteArray& key,
        const VirgilByteArray& pwd) {
    return VirgilAsymmetricCipher::checkPrivateKeyPassword(key, pwd);
}

bool VirgilKeyPair::isPrivateKeyEncrypted(const VirgilByteArray& privateKey) {
    return VirgilAsymmetricCipher::isPrivateKeyEncrypted(privateKey);
}

VirgilByteArray VirgilKeyPair::resetPrivateKeyPassword(
        const VirgilByteArray& privateKey,
        const VirgilByteArray& oldPassword, const VirgilByteArray& newPassword) {
    VirgilAsymmetricCipher cipher;
    cipher.setPrivateKey(privateKey, oldPassword);
    const bool isPEM = privateKey.front() == 0x2D;
    if (isPEM) {
        return cipher.exportPrivateKeyToPEM(newPassword);
    } else {
        return cipher.exportPrivateKeyToDER(newPassword);
    }
}

VirgilByteArray VirgilKeyPair::encryptPrivateKey(
        const virgil::crypto::VirgilByteArray& privateKey, const virgil::crypto::VirgilByteArray& privateKeyPassword) {
    if (privateKeyPassword.empty()) {
        throw virgil::crypto::make_error(VirgilCryptoError::InvalidArgument);
    }
    return VirgilKeyPair::resetPrivateKeyPassword(privateKey, VirgilByteArray(), privateKeyPassword);
}

VirgilByteArray VirgilKeyPair::decryptPrivateKey(
        const virgil::crypto::VirgilByteArray& privateKey, const virgil::crypto::VirgilByteArray& privateKeyPassword) {
    return VirgilKeyPair::resetPrivateKeyPassword(privateKey, privateKeyPassword, VirgilByteArray());
}

VirgilByteArray VirgilKeyPair::extractPublicKey(
        const virgil::crypto::VirgilByteArray& privateKey,
        const virgil::crypto::VirgilByteArray& privateKeyPassword) {
    VirgilAsymmetricCipher cipher;
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    const bool isPEM = privateKey.front() == 0x2D;
    if (isPEM) {
        return cipher.exportPublicKeyToPEM();
    } else {
        return cipher.exportPublicKeyToDER();
    }
}

VirgilByteArray VirgilKeyPair::publicKeyToPEM(const VirgilByteArray& publicKey) {
    VirgilAsymmetricCipher cipher;
    cipher.setPublicKey(publicKey);
    return cipher.exportPublicKeyToPEM();
}

VirgilByteArray VirgilKeyPair::publicKeyToDER(const VirgilByteArray& publicKey) {
    VirgilAsymmetricCipher cipher;
    cipher.setPublicKey(publicKey);
    return cipher.exportPublicKeyToDER();
}

VirgilByteArray VirgilKeyPair::privateKeyToPEM(const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilAsymmetricCipher cipher;
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    return cipher.exportPrivateKeyToPEM();
}

VirgilByteArray VirgilKeyPair::privateKeyToDER(const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilAsymmetricCipher cipher;
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    return cipher.exportPrivateKeyToDER();
}

VirgilKeyPair::VirgilKeyPair(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey)
        : publicKey_(publicKey), privateKey_(privateKey) {
};

VirgilByteArray VirgilKeyPair::publicKey() const {
    return publicKey_;
}

VirgilByteArray VirgilKeyPair::privateKey() const {
    return privateKey_;
}
