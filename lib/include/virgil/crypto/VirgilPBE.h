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

#ifndef VIRGIL_CRYPTO_VIRGIL_PBE_H
#define VIRGIL_CRYPTO_VIRGIL_PBE_H

#include <cstddef>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/asn1/VirgilAsn1Compatible.h>
using virgil::crypto::asn1::VirgilAsn1Compatible;

namespace virgil { namespace crypto {

/**
 * @name Forward declarations
 */
///@{
class VirgilPBEImpl;
///@}

/**
 * @brief Provides Password-Based Cryptography. Now PKCS#5 and PKCS#12 are partially supported.
 */
class VirgilPBE : public VirgilAsn1Compatible {
public:
    /**
     * @name Constants
     */
    ///@{
    enum {
        kIterationCountMin = 1024
    };
    ///@}
public:
    /**
     * @name Creation methods
     * @brief Object creation with specific hash function.
     */
    ///@{
    /**
     * @brief Create object with PKCS#5 parameters for PBE encryption or decryption.
     * @note Recommended PKCS#5 parameters are set.
     */
    static VirgilPBE pkcs5(const VirgilByteArray& salt, size_t iterationCount = kIterationCountMin);
    /**
     * @brief Create object with PKCS#12 parameters for PBE encryption or decryption.
     * @note Recommended PKCS#12 parameters are set.
     */
    static VirgilPBE pkcs12(const VirgilByteArray& salt, size_t iterationCount = kIterationCountMin);
    ///@}
    /**
     * @name Constructor / Destructor
     */
    ///@{
    /**
     * @brief Create object with undefined algorithm.
     * @warning SHOULD be used in conjunction with VirgilAsn1Compatible interface,
     *     i.e. VirgilPBE pbe = VirgilPBE().fromAsn1(asn1);
     */
    VirgilPBE();
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilPBE() throw();
    ///@}
    /**
     * @name Encryption / Decryption
     */
    ///@{
    /**
     * @brief Encrypt data with given password.
     * @param data - data to encrypt.
     * @param pwd - password to use when generating key.
     * @return Encrypted data.
     */
    VirgilByteArray encrypt(const VirgilByteArray& data, const VirgilByteArray& pwd) const;
    /**
     * @brief Decrypt data with given password.
     * @param data - data to decrypt.
     * @param pwd - password to use when generating key.
     * @return Decrypted data.
     */
    VirgilByteArray decrypt(const VirgilByteArray& data, const VirgilByteArray& pwd) const;
    ///@}
    /**
     * @name Copy constructor / assignment operator
     * @warning Copy constructor and assignment operator create copy of the object as it was created
     *          by on of the creation methods. All changes in the internal state,
     *          that was made after creation, are not copied!
     */
    ///@{
    VirgilPBE(const VirgilPBE& other);
    VirgilPBE& operator=(const VirgilPBE& rhs);
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
     * @brief Creates and initialize PBKDF with specified type.
     * @warning Constructor CAN NOT be used directly, use one of factory methods to create apropriate cipher.
     */
    explicit VirgilPBE(int type, const VirgilByteArray& salt, size_t iterationCount);
    /**
     * @brief If internal state is not initialized with specific algorithm exception will be thrown.
     */
    void checkState() const;
    /**
     * @brief Encrypt or decrypt data depend on the mode.
     */
    VirgilByteArray process(const VirgilByteArray& data, const VirgilByteArray& pwd, int mode) const;
    /**
     * @brief Trim trailing zeros.
     */
     void trimTrailingZeros(VirgilByteArray& data) const;
    /**
     * @brief Trim padding.
     */
     void trimPadding(VirgilByteArray& data) const;
    /**
     * @brief Trim PKCS#7 padding.
     * @return true if PKCS#7 padding was detected and successfully trimmed.
     */
     bool trimPKCS7Padding(VirgilByteArray& data) const;
private:
    VirgilPBEImpl *impl_;
};

}}

#endif /* VIRGIL_CRYPTO_VIRGIL_PBE_H */
