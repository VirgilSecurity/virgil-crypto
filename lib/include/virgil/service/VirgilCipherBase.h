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

#ifndef VIRGIL_SERVICE_VIRGIL_CIPHER_BASE_H
#define VIRGIL_SERVICE_VIRGIL_CIPHER_BASE_H

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/VirgilRandom.h>
using virgil::crypto::VirgilRandom;

#include <virgil/crypto/VirgilSymmetricCipher.h>
using virgil::crypto::VirgilSymmetricCipher;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

namespace virgil { namespace service {

/**
 * @brief This class provides configuration methods to all Virgil*Cipher classes.
 */
class VirgilCipherBase {
public:
    /**
     * @brief Initialize randomization module used by encryption.
     */
    VirgilCipherBase();
    /**
     * @brief Dispose used resources.
     */
    virtual ~VirgilCipherBase() throw();
public:
    /**
     * @brief Generate Virgil Security key pair.
     * Generate Virgil Security key pair object which contains public and private keys.
     * @return Virgil Security key pair.
     */
    virtual VirgilKeyPair generateKeyPair(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Re-encrypt given encryption key with new public key.
     *
     * This method CAN be used to share encryption key to another user - the owner of the new public key.
     * @param encryptionKey - encryption key to be re-encrypted.
     * @param publicKey - new public key.
     * @param privateKey - current private key that can be used to decrypt encryption key.
     * @param privateKeyPassword - password to the current private key.
     * @return re-encrypted encryption key.
     */
    virtual VirgilByteArray reencryptKey(const VirgilByteArray& encryptionKey, const VirgilByteArray& publicKey,
            const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword = VirgilByteArray());
protected:
    /**
     * @brief Configures symmetric cipher for encryption.
     * @note If key is omitted, it randomly generated.
     * @return Encryption key.
     */
    virtual VirgilByteArray configureEncryption(VirgilSymmetricCipher& symmetricCipher,
                const VirgilByteArray& key = VirgilByteArray());
    /**
     * @brief Configures symmetric cipher for decryption.
     */
    virtual void configureDecryption(VirgilSymmetricCipher& symmetricCipher, const VirgilByteArray& key);
private:
    VirgilRandom *random_;
};

}}

#endif /* VIRGIL_SERVICE_VIRGIL_CIPHER_BASE_H */
