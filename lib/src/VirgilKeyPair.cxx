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

#include <virgil/crypto/VirgilKeyPair.h>

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
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

VirgilKeyPair VirgilKeyPair::generateFrom(
        const VirgilKeyPair& donorKeyPair, const VirgilByteArray& donorPrivateKeyPassword,
        const VirgilByteArray& newKeyPairPassword) {

    VirgilAsymmetricCipher donorCipher;
    if (!donorKeyPair.publicKey_.empty()) {
        donorCipher.setPublicKey(donorKeyPair.publicKey_);
    } else  if (!donorKeyPair.privateKey_.empty()) {
        donorCipher.setPrivateKey(donorKeyPair.privateKey_, donorPrivateKeyPassword);
    }

    VirgilAsymmetricCipher cipher;
    cipher.genKeyPairFrom(donorCipher);
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(newKeyPairPassword));
}

VirgilKeyPair VirgilKeyPair::ecNist192(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP192R1);
}

VirgilKeyPair VirgilKeyPair::ecNist224(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP224R1);
}

VirgilKeyPair VirgilKeyPair::ecNist256(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP256R1);
}

VirgilKeyPair VirgilKeyPair::ecNist384(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP384R1);
}

VirgilKeyPair VirgilKeyPair::ecNist521(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP521R1);
}

VirgilKeyPair VirgilKeyPair::ecBrainpool256(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_BP256R1);
}

VirgilKeyPair VirgilKeyPair::ecBrainpool384(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_BP384R1);
}

VirgilKeyPair VirgilKeyPair::ecBrainpool512(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_BP512R1);
}

VirgilKeyPair VirgilKeyPair::ecKoblitz192(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP192K1);
}

VirgilKeyPair VirgilKeyPair::ecKoblitz224(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP224K1);
}

VirgilKeyPair VirgilKeyPair::ecKoblitz256(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_EC_SECP256K1);
}

VirgilKeyPair VirgilKeyPair::rsa256(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_RSA_256);
}

VirgilKeyPair VirgilKeyPair::rsa512(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_RSA_512);
}

VirgilKeyPair VirgilKeyPair::rsa1024(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_RSA_1024);
}

VirgilKeyPair VirgilKeyPair::rsa2048(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_RSA_2048);
}

VirgilKeyPair VirgilKeyPair::rsa4096(const VirgilByteArray& pwd) {
    return generate(VirgilKeyPair::Type_RSA_4096);
}

bool VirgilKeyPair::isKeyPairMatch(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {
    return VirgilAsymmetricCipher::isKeyPairMatch(publicKey, privateKey, privateKeyPassword);
}

bool VirgilKeyPair::checkPrivateKeyPassword(const VirgilByteArray& key,
        const VirgilByteArray& pwd) {
    return VirgilAsymmetricCipher::checkPrivateKeyPassword(key, pwd);
}

bool VirgilKeyPair::isPrivateKeyEncrypted(const VirgilByteArray& privateKey) {
    return VirgilAsymmetricCipher::isPrivateKeyEncrypted(privateKey);
}

VirgilByteArray VirgilKeyPair::resetPrivateKeyPassword(const VirgilByteArray& privateKey,
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

VirgilKeyPair::VirgilKeyPair(const VirgilByteArray& pwd) {
    VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_Default, pwd);
    this->publicKey_ = keyPair.publicKey();
    this->privateKey_ = keyPair.privateKey();
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

