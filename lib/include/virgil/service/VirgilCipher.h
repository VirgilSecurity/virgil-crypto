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

#ifndef VIRGIL_SERVICE_VIRGIL_CIPHER_H
#define VIRGIL_SERVICE_VIRGIL_CIPHER_H

#include <virgil/service/VirgilCipherBase.h>
using virgil::service::VirgilCipherBase;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <vector>
#include <vector>

namespace virgil { namespace service {

/**
 * @brief This class provides high-level interface to encrypt / decrypt data using Virgil Security keys.
 */
class VirgilCipher : public VirgilCipherBase {
public:
    /**
     * @brief Dispose used resources.
     */
    virtual ~VirgilCipher() throw();
public:
    /**
     * @brief Encrypt given data.
     */
    VirgilByteArray encrypt(const VirgilByteArray& data);
    /**
     * @brief Decrypt given data for recipient defined by certificate id and private key.
     * @note Content info MUST be defined.
     * @see method setContentInfo().
     * @return Decrypted data.
     */
    VirgilByteArray decryptWithKey(const VirgilByteArray& encryptedData,
            const VirgilByteArray& certificateId, const VirgilByteArray& privateKey,
            const VirgilByteArray& privateKeyPassword = VirgilByteArray());
    /**
     * @brief Decrypt given data for recipient defined by password.
     * @note Content info MUST be defined.
     * @see method setContentInfo().
     * @return Decrypted data.
     */
    VirgilByteArray decryptWithPassword(const VirgilByteArray& encryptedData, const VirgilByteArray& pwd);
};

}}

#endif /* VIRGIL_SERVICE_VIRGIL_CIPHER_H */
