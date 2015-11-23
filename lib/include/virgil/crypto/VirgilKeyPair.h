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

#ifndef VIRGIL_KEY_PAIR_H
#define VIRGIL_KEY_PAIR_H

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil { namespace crypto {

/**
 * @brief This class handles information about Virgil Security key pair.
 */
class VirgilKeyPair {
public:
    /**
     * @brief Generate new key pair with 192-bits NIST curve.
     */
    static VirgilKeyPair ecNist192(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 224-bits NIST curve.
     */
    static VirgilKeyPair ecNist224(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 256-bits NIST curve.
     */
    static VirgilKeyPair ecNist256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 384-bits NIST curve.
     */
    static VirgilKeyPair ecNist384(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 521-bits NIST curve.
     */
    static VirgilKeyPair ecNist521(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 256-bits Brainpool curve.
     */
    static VirgilKeyPair ecBrainpool256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 384-bits Brainpool curve.
     */
    static VirgilKeyPair ecBrainpool384(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 512-bits Brainpool curve.
     */
    static VirgilKeyPair ecBrainpool512(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 192-bits "Koblitz" curve.
     */
    static VirgilKeyPair ecKoblitz192(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 224-bits "Koblitz" curve.
     */
    static VirgilKeyPair ecKoblitz224(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 256-bits "Koblitz" curve.
     */
    static VirgilKeyPair ecKoblitz256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 256-bits.
     */
    static VirgilKeyPair rsa256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 512-bits.
     */
    static VirgilKeyPair rsa512(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 1024-bits.
     */
    static VirgilKeyPair rsa1024(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 2048-bits.
     */
    static VirgilKeyPair rsa2048(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 4096-bits.
     */
    static VirgilKeyPair rsa4096(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with default settings.
     */
    explicit VirgilKeyPair(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Initialize key pair with given public and private key.
     */
    VirgilKeyPair(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey);
    /**
     * @brief Provide access to the public key.
     */
    VirgilByteArray publicKey() const;
    /**
     * @brief Provide access to the private key.
     */
    VirgilByteArray privateKey() const;
private:
    VirgilByteArray publicKey_;
    VirgilByteArray privateKey_;
};

}}

#endif /* VIRGIL_KEY_PAIR_H */
