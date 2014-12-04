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

#ifndef VIRGIL_SERVICE_VIRGIL_MULTIPART_CIPHER_H
#define VIRGIL_SERVICE_VIRGIL_MULTIPART_CIPHER_H

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace virgil { namespace service {

/**
 * @name Forward declarations
 */
///@{
class VirgilMultipartCipherImpl;
///@}

/**
 * @brief This class provides high-level interface to encrypt / decrypt data in multipart form
 *            using Virgil Security keys.
 */
class VirgilMultipartCipher {
public:
    /**
     * @brief Initialize randomization module used by encryption.
     */
    VirgilMultipartCipher();
    /**
     * @brief Dispose used resources.
     */
    virtual ~VirgilMultipartCipher() throw();
public:
    /**
     * @brief Initialize multipart encryption with given public key.
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
     * @brief Encrypt given data.
     * @return Encrypted data.
     */
    VirgilByteArray process(const VirgilByteArray& data);
    /**
     * @brief Finalize encryption or decryption process.
     * @return Last part of the encrypted data.
     */
    VirgilByteArray finish();
private:
    /**
     * @brief Deny copy constructor.
     */
    VirgilMultipartCipher(const VirgilMultipartCipher& other);
    /**
     * @brief Deny asignment operator.
     */
    VirgilMultipartCipher& operator=(const VirgilMultipartCipher& right);
private:
    VirgilMultipartCipherImpl *impl_;
};

}}

#endif /* VIRGIL_SERVICE_VIRGIL_MULTIPART_CIPHER_H */
