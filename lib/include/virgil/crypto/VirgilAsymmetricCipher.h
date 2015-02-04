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

#ifndef VIRGIL_CRYPTO_ASYMMETRIC_CIPHER_H
#define VIRGIL_CRYPTO_ASYMMETRIC_CIPHER_H

#include <cstddef>

#include <virgil/crypto/VirgilAsn1Compatible.h>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace virgil { namespace crypto {

/**
 * @name Forward declarations
 */
///@{
class VirgilKeyPairGenerator;
class VirgilAsymmetricCipherImpl;
///@}

/**
 * @brief Provides asymmetric ciphers algorithms (PK).
 */
class VirgilAsymmetricCipher : public VirgilAsn1Compatible {
public:
    /**
     * @name Creation methods
     */
    ///@{
    /**
     * @brief Create object that is not initialzed with specific algorithm yet.
     * @see @link genKeyPair @endlink method to initialize it.
     */
    static VirgilAsymmetricCipher none();
    /**
     * @brief Creates object that handles RSA Private-Key algorithms.
     */
    static VirgilAsymmetricCipher rsa();
    /**
     * @brief Creates object that handles Elliptic Curve Private-Key algorithms.
     */
    static VirgilAsymmetricCipher ec();
    ///@}

    /**
     * @name Info
     */
    ///@{
    /**
     * @brief Provides size in bits of the underlying key.
     * @return Size in bits of the underlying key.
     */
    size_t keySize() const;
    /**
     * @brief Provides the length in bytes of the underlying key.
     * @return Length in bytes of the underlying key.
     */
    size_t keyLength() const;
    ///@}

    /**
     * @name Keys management
     */
    ///@{
    /**
     * @brief Configures privte key.
     *
     * Parse given private key and set it to the current context.
     * @param key - private key in DER or PEM format.
     * @param pwd - private key password if exists.
     */
    void setPrivateKey(const VirgilByteArray& key, const VirgilByteArray& pwd = VirgilByteArray());
    /**
     * @brief Configures public key.
     *
     * Parse given public key and set it to the current context.
     * @param key - public key in DER or PEM format.
     */
    void setPublicKey(const VirgilByteArray& key);
    /**
     * @brief Generates private and public keys.
     *
     * Generate private and public keys in the current context.
     * @param keyPairGenerator - keypair generator that handles appropriate information about generated keys.
     */
    void genKeyPair(const VirgilKeyPairGenerator& keyPairGenerator);
    ///@}

    /**
     * @name Keys export
     */
    ///@{
    /**
     * @brief Provides private key.
     * @return Private key in a PKCS#1, SEC1 DER or PKCS#8 structure format.
     */
    VirgilByteArray exportPrivateKeyToDER(const VirgilByteArray& pwd = VirgilByteArray()) const;
    /**
     * @brief Provides public key.
     * @return Public key in the SubjectPublicKeyInfo DER structure format.
     */
    VirgilByteArray exportPublicKeyToDER() const;
    /**
     * @brief Provides private key.
     * @return Private key in a PKCS#1, SEC1 PEM or PKCS#8 structure format.
     */
    VirgilByteArray exportPrivateKeyToPEM(const VirgilByteArray& pwd = VirgilByteArray()) const;
    /**
     * @brief Provides public key.
     * @return Public key in a SubjectPublicKeyInfo PEM structure format.
     */
    VirgilByteArray exportPublicKeyToPEM() const;
    ///@}

    /**
     * @name Encryption / Decryption
     */
     ///@{
    /**
     * @brief Encrypts given message.
     *
     * Encrypt given message with known public key, configured with @link setPublicKey @endlink method,
     *     or @link genKeyPair @endlink method.
     *
     * @param in - message to be encrypted.
     * @return Encrypted message.
     */
    VirgilByteArray encrypt(const VirgilByteArray& in) const;
    /**
     * @brief Decrypts given message.
     *
     * Decrypt given message with known private key, configured with @link setPrivateKey @endlink method,
     *     or @link genKeyPair @endlink method.
     *
     * @param in - message to be decrypted.
     * @return Decrypted message.
     */
    VirgilByteArray decrypt(const VirgilByteArray& in) const;
     ///@}

    /**
     * @name Sign / Verify
     */
     ///@{
    /**
     * @brief Sign given hash.
     *
     * Sign given hash with known private key, configured with @link setPrivateKey @endlink method,
     *     or @link genKeyPair @endlink method.
     *
     * @param hash - digest to be signed.
     * @return Signed digest.
     */
    VirgilByteArray sign(const VirgilByteArray& hash) const;
    /**
     * @brief Verify given hash with given sign.
     *
     * Verify given hash with known public key, configured with @link setPrivateKey @endlink method,
     *     or @link genKeyPair @endlink method, and with given sign.
     *
     * @param hash - digest to be verified.
     * @param sign - signed digest to be used during vefification.
     * @return true if given hash corresponds to the given signed digest, otherwise - false.
     */
    bool verify(const VirgilByteArray& hash, const VirgilByteArray& sign) const;
    ///@}
    /**
     * @name Copy constructor / assignment operator
     * @warning Copy constructor and assignment operator create copy of the object as it was created
     *          by on of the creation methods. All changes in the internal state,
     *          that was made after creation, are not copied!
     */
    ///@{
    VirgilAsymmetricCipher(const VirgilAsymmetricCipher& other);
    VirgilAsymmetricCipher& operator=(const VirgilAsymmetricCipher& rhs);
    ///@}
    /**
     * @name VirgilAsn1Compatible implementation
     */
    ///@{
    virtual VirgilByteArray toAsn1() const;
    virtual void fromAsn1(const VirgilByteArray& asn1);
    ///@}
private:
    /**
     * @brief Creates and initialize cipher with given type.
     * @warning CAN NOT be used directly, use one of the factory methods to create apropriate cipher.
     */
    explicit VirgilAsymmetricCipher(int type);
    /**
     * @brief If internal state is not initialized with specific algorithm exception will be thrown.
     */
    void checkState() const;
public:
    virtual ~VirgilAsymmetricCipher() throw();
private:
    VirgilAsymmetricCipherImpl *impl_;
};

}}

#endif /* VIRGIL_CRYPTO_ASYMMETRIC_CIPHER_H */
