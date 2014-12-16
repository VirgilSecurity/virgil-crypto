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

#include <utility>
using std::pair;
using std::make_pair;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

#include <virgil/crypto/VirgilRandom.h>
using virgil::crypto::VirgilRandom;

#include <virgil/crypto/VirgilKDF.h>
using virgil::crypto::VirgilKDF;

#include <virgil/crypto/VirgilSymmetricCipher.h>
using virgil::crypto::VirgilSymmetricCipher;

#include <virgil/crypto/VirgilKeyPairGenerator.h>
using virgil::crypto::VirgilKeyPairGenerator;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

/**
 * @name Configuration constants.
 */
///@{
static const VirgilKeyPairGenerator::ECKeyGroup kKeyPair_ECKeyGroup =
        VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1;
static const VirgilSymmetricCipher::VirgilSymmetricCipherPadding kSymmetricCipher_Padding =
        VirgilSymmetricCipher::VirgilSymmetricCipherPadding_PKCS7;
static const unsigned char kSymmetricCipher_IV_Value = 0x00;
///@}

VirgilCipherBase::VirgilCipherBase() : random_(
        new VirgilRandom(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(std::string("virgil::service::VirgilCipherBase")))) {
}

VirgilCipherBase::~VirgilCipherBase() throw() {
    if (random_) {
        delete random_;
    }
}

VirgilKeyPair VirgilCipherBase::generateKeyPair(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::ec();
    asymmetricCipher.genKeyPair(VirgilKeyPairGenerator::ec(kKeyPair_ECKeyGroup));
    VirgilByteArray publicKey = asymmetricCipher.exportPublicKeyToPEM();
    VirgilByteArray privateKey = asymmetricCipher.exportPrivateKeyToPEM(pwd);
    return VirgilKeyPair(publicKey, privateKey);
}

VirgilByteArray VirgilCipherBase::reencryptKey(const VirgilByteArray& encryptionKey, const VirgilByteArray& publicKey,
            const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {

    VirgilAsymmetricCipher encryptionCipher = VirgilAsymmetricCipher::none();
    encryptionCipher.setPublicKey(publicKey);

    VirgilAsymmetricCipher decriptioncCipher = VirgilAsymmetricCipher::none();
    decriptioncCipher.setPrivateKey(privateKey, privateKeyPassword);

    return encryptionCipher.encrypt(decriptioncCipher.decrypt(encryptionKey));
}

VirgilByteArray VirgilCipherBase::configureEncryption(VirgilSymmetricCipher& symmetricCipher, const VirgilByteArray& key) {
    symmetricCipher.clear();
    VirgilByteArray iv(symmetricCipher.ivSize(), kSymmetricCipher_IV_Value);
    VirgilByteArray encryptionKey = key.empty() ? random_->randomize(symmetricCipher.keyLength()) : key;
    symmetricCipher.setEncryptionKey(encryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.setIV(iv);
    symmetricCipher.reset();
    return encryptionKey;
}

void VirgilCipherBase::configureDecryption(VirgilSymmetricCipher& symmetricCipher, const VirgilByteArray& key) {
    symmetricCipher.clear();
    VirgilByteArray iv(symmetricCipher.ivSize(), kSymmetricCipher_IV_Value);
    symmetricCipher.setDecryptionKey(key);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.setIV(iv);
    symmetricCipher.reset();
}
