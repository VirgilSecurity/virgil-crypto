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

#ifndef VIRGIL_CRYPTO_ASYMMETRIC_CIPHER_H
#define VIRGIL_CRYPTO_ASYMMETRIC_CIPHER_H

#include <cstdlib>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Compatible.h>

namespace virgil { namespace crypto { namespace foundation {

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
class VirgilAsymmetricCipher : public virgil::crypto::foundation::asn1::VirgilAsn1Compatible {
public:
    /**
     * @name Creation methods
     */
    ///@{
    /**
     * @brief Create object that is not initialized with specific algorithm yet.
     * @see fromAsn1() method to initialize it.
     * @see genKeyPair() method to initialize it.
     * @see setPublicKey() method to initialize it.
     * @see setPrivateKey() method to initialize it.
     */
    VirgilAsymmetricCipher();
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
    static bool isKeyPairMatch(
            const virgil::crypto::VirgilByteArray& publicKey,
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
    static bool checkPrivateKeyPassword(
            const virgil::crypto::VirgilByteArray& key,
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
     * @name Keys management
     */
    ///@{
    /**
     * @brief Configures private key.
     *
     * Parse given private key and set it to the current context.
     * @param key - private key in DER or PEM format.
     * @param pwd - private key password if exists.
     */
    void setPrivateKey(
            const virgil::crypto::VirgilByteArray& key,
            const virgil::crypto::VirgilByteArray& pwd = virgil::crypto::VirgilByteArray());

    /**
     * @brief Configures public key.
     *
     * Parse given public key and set it to the current context.
     * @param key - public key in DER or PEM format.
     */
    void setPublicKey(const virgil::crypto::VirgilByteArray& key);

    /**
     * @brief Generates private and public keys.
     *
     * Generate private and public keys in the current context.
     * @param type - keypair type.
     */
    void genKeyPair(VirgilKeyPair::Type type);

    /**
     * @brief Generates private and public keys of the same type from the given context.
     *
     * @param other - donor context.
     * @throw VirgilCryptoException - if donor context does not contain own key pair.
     */
    void genKeyPairFrom(const VirgilAsymmetricCipher& other);

    /**
     * @brief Compute shared secret key on a given contexts.
     *
     * @param publicContext - public context.
     * @param privateContext - private context.
     * @throw VirgilCryptoException - if public context does not contain public key.
     * @throw VirgilCryptoException - if private context does not contain private key.
     */
    static VirgilByteArray computeShared(
            const VirgilAsymmetricCipher& publicContext,
            const VirgilAsymmetricCipher& privateContext);
    ///@}

    /**
     * @name Keys export
     */
    ///@{
    /**
     * @brief Provides private key.
     * @param pwd - private key password (max length is 31 byte).
     * @return Private key in a PKCS#1, SEC1 DER or PKCS#8 structure format.
     */
    virgil::crypto::VirgilByteArray exportPrivateKeyToDER(
            const virgil::crypto::VirgilByteArray& pwd = virgil::crypto::VirgilByteArray()) const;

    /**
     * @brief Provides public key.
     * @return Public key in the SubjectPublicKeyInfo DER structure format.
     */
    virgil::crypto::VirgilByteArray exportPublicKeyToDER() const;

    /**
     * @brief Provides private key.
     * @param pwd - private key password (max length is 31 byte).
     * @return Private key in a PKCS#1, SEC1 PEM or PKCS#8 structure format.
     */
    virgil::crypto::VirgilByteArray exportPrivateKeyToPEM(
            const virgil::crypto::VirgilByteArray& pwd = virgil::crypto::VirgilByteArray()) const;

    /**
     * @brief Provides public key.
     * @return Public key in a SubjectPublicKeyInfo PEM structure format.
     */
    virgil::crypto::VirgilByteArray exportPublicKeyToPEM() const;
    ///@}

    /**
     * @name Keys low level management
     *
     * @note Properly works only with Curve25519 keys.
     * @warning Used for internal purposes only.
     */
    ///@{
    /**
     * @brief Return type of the underlying key.
     * @note Properly works only with Curve25519 keys.
     */
    virgil::crypto::VirgilKeyPair::Type getKeyType() const;

    /**
     * @brief Change type of the underlying key.
     * @note Properly works only with Curve25519 keys.
     */
    void setKeyType(virgil::crypto::VirgilKeyPair::Type keyType);

    /**
     * @brief Return number of the underlying public key.
     *
     * Legend:
     *     * number - EC point if underlying key belongs to the Elliptic Curve group
     *
     * @note Properly works only with Curve25519 keys.
     */
    virgil::crypto::VirgilByteArray getPublicKeyBits() const;

    /**
     * @brief Set number of the underlying public key.
     *
     * Legend:
     *     * number - EC point if underlying key belongs to the Elliptic Curve group
     *
     * @note Properly works only with Curve25519 keys.
     */
    void setPublicKeyBits(const virgil::crypto::VirgilByteArray& bits);

    /**
     * @brief Return number of the given sign.
     *
     * Legend:
     *     * number - (r,s) if underlying key belongs to the Elliptic Curve group
     *
     * @note Properly works only with Curve25519 keys.
     */
    virgil::crypto::VirgilByteArray signToBits(const virgil::crypto::VirgilByteArray& sign);

    /**
     * @brief Make sign from the given number.
     *
     * Legend:
     *     * number - (r,s) if underlying key belongs to the Elliptic Curve group
     *
     * @note Properly works only with Curve25519 keys.
     */
    virgil::crypto::VirgilByteArray signFromBits(const virgil::crypto::VirgilByteArray& bits);
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
    virgil::crypto::VirgilByteArray encrypt(const virgil::crypto::VirgilByteArray& in) const;

    /**
     * @brief Decrypts given message.
     *
     * Decrypt given message with known private key, configured with @link setPrivateKey @endlink method,
     *     or @link genKeyPair @endlink method.
     *
     * @param in - message to be decrypted.
     * @return Decrypted message.
     */
    virgil::crypto::VirgilByteArray decrypt(const virgil::crypto::VirgilByteArray& in) const;
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
     * @param digest - digest to be signed.
     * @param hashType - type of the hash algorithm that was used to get digest
     * @return Signed digest.
     */
    virgil::crypto::VirgilByteArray sign(const virgil::crypto::VirgilByteArray& digest, int hashType) const;

    /**
     * @brief Verify given hash with given sign.
     *
     * Verify given hash with known public key, configured with @link setPrivateKey @endlink method,
     *     or @link genKeyPair @endlink method, and with given sign.
     *
     * @param digest - digest to be verified.
     * @param sign - signed digest to be used during verification.
     * @param hashType - type of the hash algorithm that was used to get digest
     * @return true if given digest corresponds to the given digest sign, otherwise - false.
     */
    bool verify(
            const virgil::crypto::VirgilByteArray& digest,
            const virgil::crypto::VirgilByteArray& sign, int hashType) const;
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
    virtual size_t asn1Write(
            virgil::crypto::foundation::asn1::VirgilAsn1Writer& asn1Writer,
            size_t childWrittenBytes = 0) const;

    virtual void asn1Read(virgil::crypto::foundation::asn1::VirgilAsn1Reader& asn1Reader);
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
    VirgilAsymmetricCipherImpl* impl_;
};

}}}

#endif /* VIRGIL_CRYPTO_ASYMMETRIC_CIPHER_H */
