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


#include <virgil/crypto/primitive/VirgilOperationCipher.h>

#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::primitive::VirgilOperationCipher;
using virgil::crypto::foundation::VirgilSymmetricCipher;

namespace {

class VirgilSymmetricCipherWrapper {
public:

    VirgilSymmetricCipherWrapper()
            : cipherAlgorithm_(VirgilSymmetricCipher::Algorithm::AES_256_GCM) {}

    size_t getKeySize() const {
        VirgilSymmetricCipher cipher(cipherAlgorithm_);
        return cipher.keyLength();
    }

    size_t getNonceSize() const {
        VirgilSymmetricCipher cipher(cipherAlgorithm_);
        return cipher.ivSize();
    }

    VirgilByteArray encrypt(
            const VirgilByteArray& plainText, const VirgilByteArray& key, const VirgilByteArray& nonce,
            const VirgilByteArray& authData) const {

        VirgilSymmetricCipher cipher(cipherAlgorithm_);
        cipher.setEncryptionKey(key);
        cipher.setIV(nonce);
        cipher.setAuthData(authData);
        cipher.reset();

        auto cipherText = VirgilByteArray();
        virgil::crypto::bytes_append(cipherText, cipher.update(plainText));
        virgil::crypto::bytes_append(cipherText, cipher.finish());
        return cipherText;
    }

    VirgilByteArray decrypt(
            const VirgilByteArray& cipherText, const VirgilByteArray& key, const VirgilByteArray& nonce,
            const VirgilByteArray& authData) const {

        VirgilSymmetricCipher cipher(cipherAlgorithm_);
        cipher.setDecryptionKey(key);
        cipher.setIV(nonce);
        cipher.setAuthData(authData);
        cipher.reset();

        auto plainText = VirgilByteArray();
        virgil::crypto::bytes_append(plainText, cipher.update(cipherText));
        virgil::crypto::bytes_append(plainText, cipher.finish());
        return plainText;
    }

private:
    VirgilSymmetricCipher::Algorithm cipherAlgorithm_;
};

}

VirgilOperationCipher VirgilOperationCipher::getDefault() {
    return VirgilOperationCipher(VirgilSymmetricCipherWrapper());
}
