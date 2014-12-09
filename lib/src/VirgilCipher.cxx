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

#include <virgil/service/VirgilCipher.h>
using virgil::service::VirgilCipher;

#include <cstring>

#include <string>
using std::string;

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
///@}

namespace virgil { namespace service {

class VirgilCipherImpl {
public:
    VirgilCipherImpl(const VirgilByteArray& moduleName) : random(moduleName) {}
public:
    VirgilRandom random;
};

}}

VirgilCipher::VirgilCipher() : impl_(0) {
    const char * moduleName = "virgil::service::VirgilCipher";
    impl_ = new VirgilCipherImpl(
            VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN((const unsigned char *)moduleName, strlen(moduleName)));
}

VirgilCipher::~VirgilCipher() throw() {
    if (impl_) {
        delete impl_;
    }
}

VirgilKeyPair VirgilCipher::generateKeyPair(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::ec();
    asymmetricCipher.genKeyPair(VirgilKeyPairGenerator::ec(kKeyPair_ECKeyGroup));
    VirgilByteArray publicKey = asymmetricCipher.exportPublicKeyToPEM();
    VirgilByteArray privateKey = asymmetricCipher.exportPrivateKeyToPEM(pwd);
    return VirgilKeyPair(publicKey, privateKey);
}

VirgilByteArray VirgilCipher::reencryptKey(const VirgilByteArray& encryptionKey, const VirgilByteArray& publicKey,
            const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {

    VirgilAsymmetricCipher encryptionCipher = VirgilAsymmetricCipher::none();
    encryptionCipher.setPublicKey(publicKey);

    VirgilAsymmetricCipher decriptioncCipher = VirgilAsymmetricCipher::none();
    decriptioncCipher.setPrivateKey(privateKey, privateKeyPassword);

    return encryptionCipher.encrypt(decriptioncCipher.decrypt(encryptionKey));
}

VirgilByteArray VirgilCipher::encrypt(VirgilDataSource& source, VirgilDataSink& sink,
        const VirgilByteArray& publicKey) {

    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();

    VirgilByteArray encryptionKey = impl_->random.randomize(symmetricCipher.keyLength());
    symmetricCipher.setEncryptionKey(encryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    while (source.hasData() && sink.isGood()) {
        sink.write(symmetricCipher.update(source.read()));
    }
    if (sink.isGood()) {
        sink.write(symmetricCipher.finish());
    }

    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPublicKey(publicKey);
    return asymmetricCipher.encrypt(encryptionKey);
}

void VirgilCipher::decrypt(VirgilDataSource& source, VirgilDataSink& sink,
        const VirgilByteArray& encryptionKey,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {

    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPrivateKey(privateKey, privateKeyPassword);

    VirgilByteArray decryptionKey = asymmetricCipher.decrypt(encryptionKey);

    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();
    symmetricCipher.setDecryptionKey(decryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    while (source.hasData() && sink.isGood()) {
        sink.write(symmetricCipher.update(source.read()));
    }
    if (sink.isGood()) {
        sink.write(symmetricCipher.finish());
    }
}

VirgilByteArray VirgilCipher::encryptWithPassword(const VirgilByteArray& data, const VirgilByteArray& pwd) {
    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();

    VirgilByteArray encryptionKey = VirgilKDF::kdf1(pwd, symmetricCipher.keyLength());
    symmetricCipher.setEncryptionKey(encryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    VirgilByteArray firstChunk = symmetricCipher.update(data);
    VirgilByteArray secondChunk = symmetricCipher.finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), secondChunk.begin(), secondChunk.end());
    return result;
}

VirgilByteArray VirgilCipher::decryptWithPassword(const VirgilByteArray& data, const VirgilByteArray& pwd) {
    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();

    VirgilByteArray decryptionKey = VirgilKDF::kdf1(pwd, symmetricCipher.keyLength());
    symmetricCipher.setDecryptionKey(decryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    VirgilByteArray firstChunk = symmetricCipher.update(data);
    VirgilByteArray secondChunk = symmetricCipher.finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), secondChunk.begin(), secondChunk.end());
    return result;
}
