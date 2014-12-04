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

#ifndef VIRGIL_CRYPTO_KEY_PAIR_GENERATOR_H
#define VIRGIL_CRYPTO_KEY_PAIR_GENERATOR_H

#include <cstddef>

namespace virgil { namespace crypto {

/**
 * @class KeyPairGenerator
 * @brief Encapsulates specific keypair information and way to create it.
 *
 * This class performs a simple way to generate keypair with a given information,
 *     i.e. RSA key size, or encryption group for elliptic curve keys.
 */
class VirgilKeyPairGenerator {
public:
    /**
     * @brief Reprenesents type of underlying keypair.
     */
    typedef enum {
        VirgilKeyPairType_None = 0,   /**< Underlying keypair type is not defined */
        VirgilKeyPairType_RSA,        /**< Underlying keypair type is RSA         */
        VirgilKeyPairType_EC          /**< Underlying keypair type is EC          */
    } VirgilKeyPairType;
    /**
     * @brief Reprenesents type of underlying keypair.
     */
    typedef enum {
        ECKeyGroup_DP_NONE = 0,
        ECKeyGroup_DP_SECP192R1,      /**< 192-bits NIST curve */
        ECKeyGroup_DP_SECP224R1,      /**< 224-bits NIST curve */
        ECKeyGroup_DP_SECP256R1,      /**< 256-bits NIST curve */
        ECKeyGroup_DP_SECP384R1,      /**< 384-bits NIST curve */
        ECKeyGroup_DP_SECP521R1,      /**< 521-bits NIST curve */
        ECKeyGroup_DP_BP256R1,        /**< 256-bits Brainpool curve */
        ECKeyGroup_DP_BP384R1,        /**< 384-bits Brainpool curve */
        ECKeyGroup_DP_BP512R1,        /**< 512-bits Brainpool curve */
        ECKeyGroup_DP_M221,           /**< (not implemented yet)    */
        ECKeyGroup_DP_M255,           /**< Curve25519               */
        ECKeyGroup_DP_M383,           /**< (not implemented yet)    */
        ECKeyGroup_DP_M511,           /**< (not implemented yet)    */
        ECKeyGroup_DP_SECP192K1,      /**< 192-bits "Koblitz" curve */
        ECKeyGroup_DP_SECP224K1,      /**< 224-bits "Koblitz" curve */
        ECKeyGroup_DP_SECP256K1,      /**< 256-bits "Koblitz" curve */
    } ECKeyGroup;

public:
    /**
     * @name Factory methods
     * @brief Creation methods for specific keypair.
     */
    ///@{
    static VirgilKeyPairGenerator rsa(size_t nbits);
    static VirgilKeyPairGenerator ec(ECKeyGroup ecKeyGroup);
    ///@}
    /**
     * @name Info
     */
     ///@{
    /**
     * @brief Return keypair type.
     * @return Underlying keypair type.
     */
    VirgilKeyPairType type() const;
    /**
     * @brief Return RSA key size.
     * @return RSA key size in bits if @link type() @endlink is VirgilKeyPairType_RSA, zero - otherwise.
     */
    size_t rsaKeySize() const;
    /**
     * @brief Return elliptic curve group identifier.
     * @return EC group id if @link type() @endlink is VirgilKeyPairType_EC, ECKeyGroup_DP_NONE - otherwise.
     */
    ECKeyGroup ecKeyGroup() const;
    ///@}
    /**
     * @name KeyPair generation
     */
    ///@{
    /**
     * @brief Generate keypair depends on the given information.
     * @param ctx - context where keypair will be generated - MUST be of type pk_context.
     * @warning Is used for internal purposes only.
     */
    void generate(void *ctx) const;
    ///@}
private:
    /**
     * @brief Creates key pair object with a given type and value.
     * @param type - type of generated key.
     * @param value - type specific value:
     *     - RSA key size in bits if type is equal to VirgilKeyPairType_RSA.
     *     - EC group id if type is equal to VirgilKeyPairType_EC.
     * @warning CAN NOT be used directly, use any of factory methods.
     */
    VirgilKeyPairGenerator(VirgilKeyPairType type, size_t value);
private:
    VirgilKeyPairType type_;
    size_t value_;
};

}}

#endif /* VIRGIL_CRYPTO_KEY_PAIR_GENERATOR_H */
