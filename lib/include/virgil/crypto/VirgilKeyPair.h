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
     * @brief Type if the keypair.
     */
    enum Type {
        Type_Default = 0,       /**< recommended most safe type */
        Type_RSA_256,           /**< RSA 1024 bit (not recommended) */
        Type_RSA_512,           /**< RSA 1024 bit (not recommended) */
        Type_RSA_1024,          /**< RSA 1024 bit (not recommended) */
        Type_RSA_2048,          /**< RSA 2048 bit (not recommended) */
        Type_RSA_3072,          /**< RSA 3072 bit */
        Type_RSA_4096,          /**< RSA 4096 bit */
        Type_RSA_8192,          /**< RSA 8192 bit */
        Type_EC_SECP192R1,      /**< 192-bits NIST curve */
        Type_EC_SECP224R1,      /**< 224-bits NIST curve */
        Type_EC_SECP256R1,      /**< 256-bits NIST curve */
        Type_EC_SECP384R1,      /**< 384-bits NIST curve */
        Type_EC_SECP521R1,      /**< 521-bits NIST curve */
        Type_EC_BP256R1,        /**< 256-bits Brainpool curve */
        Type_EC_BP384R1,        /**< 384-bits Brainpool curve */
        Type_EC_BP512R1,        /**< 512-bits Brainpool curve */
        Type_EC_CURVE25519,     /**< Curve25519               */
        Type_EC_SECP192K1,      /**< 192-bits "Koblitz" curve */
        Type_EC_SECP224K1,      /**< 224-bits "Koblitz" curve */
        Type_EC_SECP256K1,      /**< 256-bits "Koblitz" curve */
    };
public:
    /**
     * @brief Generate new key pair given type.
     * @param type - private key type to be generated.
     * @param pwd - private key password (max length is 31 byte).
     */
    static VirgilKeyPair generate(VirgilKeyPair::Type type = VirgilKeyPair::Type_Default,
            const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 192-bits NIST curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecNist192(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 224-bits NIST curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecNist224(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 256-bits NIST curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecNist256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 384-bits NIST curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecNist384(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 521-bits NIST curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecNist521(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 256-bits Brainpool curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecBrainpool256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 384-bits Brainpool curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecBrainpool384(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 512-bits Brainpool curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecBrainpool512(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 192-bits "Koblitz" curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecKoblitz192(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 224-bits "Koblitz" curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecKoblitz224(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with 256-bits "Koblitz" curve.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair ecKoblitz256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 256-bits.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair rsa256(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 512-bits.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair rsa512(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 1024-bits.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair rsa1024(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 2048-bits.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair rsa2048(const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Generate new key pair with RSA 4096-bits.
     * @deprecated Use generate() instead.
     */
    static VirgilKeyPair rsa4096(const VirgilByteArray& pwd = VirgilByteArray());

    /**
     * @name Keys validation
     */
    ///@{
    /**
     * @brief Check if a public-private pair of keys matches.
     *
     * @param publicKey - public key in DER or PEM format.
     * @param privateKey - private key in DER or PEM format.
     * @param privateKeyPassword - private key password if exists.
     *
     * @return true - if public-private pair of keys matches.
     */
    static bool isKeyPairMatch(const virgil::crypto::VirgilByteArray& publicKey,
            const virgil::crypto::VirgilByteArray& privateKey,
            const virgil::crypto::VirgilByteArray& privateKeyPassword = virgil::crypto::VirgilByteArray());
    /**
     * @brief Check if given private key and it's password matches.
     *
     * @param key - private key in DER or PEM format.
     * @param pwd - private key password.
     *
     * @return true - if private key and it's password matches.
     */
    static bool checkPrivateKeyPassword(const virgil::crypto::VirgilByteArray& key,
            const virgil::crypto::VirgilByteArray& pwd);
    /**
     * @brief Check if given private key is encrypted.
     *
     * @param privateKey - private key in DER or PEM format.
     *
     * @return true - if private key is encrypted.
     */
    static bool isPrivateKeyEncrypted(const virgil::crypto::VirgilByteArray& privateKey);
    ///@}

    /**
     * @brief Generate new key pair with default settings.
     * @deprecated Use generate() with default type instead.
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
