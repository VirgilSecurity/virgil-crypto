/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#ifndef VIRGIL_CRYPTO_VIRGIL_ASN1_ALG_H
#define VIRGIL_CRYPTO_VIRGIL_ASN1_ALG_H

#include <cstdlib>

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil { namespace crypto { namespace foundation { namespace asn1 { namespace internal {

/**
 * @brief This class provides methods to generate defined ASN.1 structure.
 */
class VirgilAsn1Alg {
public:
    /**
     * @brief Create PKCS#5 PBES2 ASN.1 structure with given parameters
     *
     * @param salt - PBKDF2 salt
     * @param iterationCount - PBKDF2 iteration count
     * @return PKCS#5 PBES2 ASN.1 structure
     *
     * @code
     * Generated structure:
     *     pbes2 ::= SEQUENCE {
     *       id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13},
     *       PBES2-params ::= SEQUENCE {
     *          keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
     *          encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
     *     }
     *
     *     PBES2-KDFs ALGORITHM-IDENTIFIER ::=
     *         { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
     *
     *     PBKDF2-params ::= SEQUENCE {
     *            salt CHOICE {
     *                specified OCTET STRING,
     *                otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
     *            },
     *            iterationCount INTEGER (1..MAX),
     *            keyLength INTEGER (1..MAX) OPTIONAL,
     *            prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
     *            algid-hmacWithSHA1 }
     *
     *     PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
     * @endcode
     */
    static VirgilByteArray buildPKCS5(const VirgilByteArray& salt, size_t iterationCount);

    /**
     * @brief Create PKCS#12 PBE ASN.1 structure with given parameters
     *
     * @param salt - PKCS#12 salt
     * @param iterationCount - PKCS#12 iteration count
     * @return PKCS#12 PBE ASN.1 structure
     *
     * @code
     * Generated structure:
     *     pkcs-12Pbe ::= SEQUENCE {
     *         pkcs-12PbeId OBJECT IDENTIFIER ::= {{pkcs-12PbeIds}},
     *         pkcs-12PbeParams ::= SEQUENCE {
     *             salt        OCTET STRING,
     *             iterations  INTEGER
     *         }
     *     }
     * @endcode
     */
    static VirgilByteArray buildPKCS12(const VirgilByteArray& salt, size_t iterationCount);

private:
    /**
     * @brief Initialize internal state.
     */
    VirgilAsn1Alg();
};

}}}}}

#endif /* VIRGIL_CRYPTO_VIRGIL_ASN1_ALG_H */
