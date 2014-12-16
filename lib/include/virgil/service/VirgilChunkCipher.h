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

#ifndef VIRGIL_SERVICE_VIRGIL_CHUNK_CIPHER_H
#define VIRGIL_SERVICE_VIRGIL_CHUNK_CIPHER_H

#include <cstddef>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/VirgilCipherBase.h>
using virgil::service::VirgilCipherBase;

#include <virgil/crypto/VirgilSymmetricCipher.h>
using virgil::crypto::VirgilSymmetricCipher;

namespace virgil { namespace service {

/**
 * @brief This class provides high-level interface to encrypt / decrypt data splitted to chunks.
 * @note Virgil Security keys is used for encryption and decryption.
 * @note This class algorithms are not compatible with VirgilCipher and VirgilStreamCipher class algorithms.
 */
class VirgilChunkCipher : public VirgilCipherBase {
public:
    /**
     * @brief Initialize randomization module used by encryption.
     */
    VirgilChunkCipher();
    /**
     * @brief Dispose used resources.
     */
    virtual ~VirgilChunkCipher() throw();
public:
    /**
     * @brief Adjust given chunk size to use it during encryption.
     * @param preferredChunkSize - preferred chunk size be used during encryption to split big data.
     * @return Adjusted chunk size that SHOULD be used during encryption to split plain data.
     */
    size_t adjustEncryptionChunkSize(size_t preferredChunkSize) const;
    /**
     * @brief Adjust given chunk size to use it during decryption.
     * @param encryptionChunkSize - chunk size that was used during encryption to split big data.
     * @return Adjusted chunk size that SHOULD be used during decryption to split encrypted data.
     */
    size_t adjustDecryptionChunkSize(size_t encryptionChunkSize) const;
    /**
     * @brief Initialize data chunk encryption with given public key.
     * @return encryption key - key that is used for symmetric encryption,
     *             and is encrypted by public key for security transfer via public networks.
     */
    VirgilByteArray startEncryption(const VirgilByteArray& publicKey);
    /**
     * @brief Initialize multipart decryption with given private key.
     */
    void startDecryption(const VirgilByteArray& encryptionKey, const VirgilByteArray& privateKey,
                const VirgilByteArray& privateKeyPassword = VirgilByteArray());
    /**
     * @brief Encrypt / Decrypt given data chunk.
     * @return Encrypted / Decrypted data chunk.
     */
    VirgilByteArray process(const VirgilByteArray& data);
    /**
     * @brief Finalize encryption or decryption process.
     * @note Call this method after encryption or decryption are done to prevent security issues.
     */
     void finalize();
private:
    VirgilSymmetricCipher symmetricCipher_;
};

}}

#endif /* VIRGIL_SERVICE_VIRGIL_CHUNK_CIPHER_H */
