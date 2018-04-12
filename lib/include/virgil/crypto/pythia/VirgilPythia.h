/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#ifndef virgilPythiaH
#define virgilPythiaH

#include "../VirgilByteArray.h"
#include "VirgilPythiaBlindResult.h"
#include "VirgilPythiaContext.h"
#include "VirgilPythiaDeblindResult.h"
#include "VirgilPythiaGetPasswordUpdateTokenResult.h"
#include "VirgilPythiaProveResult.h"
#include "VirgilPythiaTransformResult.h"
#include "VirgilPythiaUpdateDeblindedWithTokenResult.h"
#include "VirgilPythiaVerifyResult.h"

namespace virgil {
namespace crypto {
namespace pythia {

/**
 * @brief This class provides PYTHIA cryptographic functions and primitives.
 *
 * PYTHIA is a verifiable, cryptographic protocol that hardens passwords
 * with the help of a remote service.
 *
 * @ingroup pythia
 */
class VirgilPythia {
public:

    /**
     * @brief Blinds password.
     *
     * Turns password into a pseudo-random string.
     * This step is necessary to prevent 3rd-parties from knowledge of end user's password.
     *
     * @param password - end user's password.
     * @return VirgilPythiaBlindResult
     */
    VirgilPythiaBlindResult blind(const VirgilByteArray& password);

    /**
     * @brief Transforms blinded password using the private key, generated from pythiaSecret + pythiaScopeSecret.
     *
     * @param blindedPassword - G1 password obfuscated into a pseudo-random string.
     * @param transformationKeyID - ensemble key ID used to enclose operations in subsets.
     * @param tweak - some random value used to transform a password
     * @param pythiaSecret - global common for all secret random Key.
     * @param pythiaScopeSecret - ensemble secret generated and versioned transparently.
     *
     * @return VirgilPythiaTransformResult
     */
    VirgilPythiaTransformResult transform(
            const VirgilByteArray& blindedPassword, const VirgilByteArray& transformationKeyID,
            const VirgilByteArray& tweak, const VirgilByteArray& pythiaSecret,
            const VirgilByteArray& pythiaScopeSecret);

    /**
     * @brief Deblinds transformedPassword value with previously returned blindingSecret from blind().
     *
     * @param transformedPassword - GT transformed password from transform().
     * @param blindingSecret - BN value that was generated in blind().
     *
     * @return VirgilPythiaDeblindResult
     */
    VirgilPythiaDeblindResult
    deblind(const VirgilByteArray& transformedPassword, const VirgilByteArray& blindingSecret);

    /**
     * @brief Generates proof that server possesses secret values that were used to transform password.
     *
     * @param transformedPassword - GT transformed password from transform()
     * @param blindedPassword - G1 blinded password from blind().
     * @param transformedTweak - G2 transformed tweak from transform().
     * @param transformationPrivateKey - BN transformation private key from transform().
     *
     * @return VirgilPythiaProveResult
     */
    VirgilPythiaProveResult
    prove(const VirgilByteArray& transformedPassword, const VirgilByteArray& blindedPassword,
          const VirgilByteArray& transformedTweak, const VirgilByteArray& transformationPrivateKey);

    /**
     * @brief Verifies the output of transform().
     *
     * This operation allows client to verify that the output of transform() is correct,
     * assuming that client has previously stored tweak.
     *
     * @param transformedPassword - GT transformed password from transform()
     * @param blindedPassword - G1 blinded password from blind().
     * @param tweak - tweak from transform()
     * @param transformationPublicKey - G1 transformation public key from prove()
     * @param proofValueC - BN proof value C from prove()
     * @param proofValueU - BN proof value U from prove()
     *
     * @return VirgilPythiaVerifyResult
     */
    VirgilPythiaVerifyResult
    verify(const VirgilByteArray& transformedPassword, const VirgilByteArray& blindedPassword,
           const VirgilByteArray& tweak, const VirgilByteArray& transformationPublicKey,
           const VirgilByteArray& proofValueC, const VirgilByteArray& proofValueU);

    /**
     * @brief Updates transformationKeyID, pythiaSecret and scopeSecret.
     *
     * Rotates previousTransformationKeyID, previousPythiaSecret, previousPythiaScopeSecret and generates a
     * passwordUpdateToken that can update deblindedPassword. This action should increment version of
     * the pythiaScopeSecret.
     *
     * @param previousTransformationKeyID - previous transformation key id
     * @param previousPythiaSecret - previous pythia secret
     * @param previousPythiaScopeSecret - previous pythia scope secret
     * @param newTransformationKeyID - new transformation key id
     * @param newPythiaSecret - new pythia secret
     * @param newPythiaScopeSecret - new pythia scope secret
     *
     * @return VirgilPythiaGetPasswordUpdateTokenResult
     */
    VirgilPythiaGetPasswordUpdateTokenResult getPasswordUpdateToken(
            const VirgilByteArray& previousTransformationKeyID,
            const VirgilByteArray& previousPythiaSecret,
            const VirgilByteArray& previousPythiaScopeSecret,
            const VirgilByteArray& newTransformationKeyID, const VirgilByteArray& newPythiaSecret,
            const VirgilByteArray& newPythiaScopeSecret);

    /**
     * @brief Updates previously stored deblindedPassword with passwordUpdateToken.
     *
     * After this call, transform() called with new arguments will return corresponding values.
     *
     * @param deblindedPassword - GT previous deblinded password from deblind().
     * @param passwordUpdateToken - BN password update token from getPasswordUpdateToken().
     *
     * @return VirgilPythiaUpdateDeblindedWithTokenResult
     */
    VirgilPythiaUpdateDeblindedWithTokenResult updateDeblindedWithToken(
            const VirgilByteArray& deblindedPassword, const VirgilByteArray& passwordUpdateToken);

private:
    VirgilPythiaContext pythiaContext;
};

} // namespace pythia
} // namespace crypto
} // namespace virgil

#endif /* virgilPythiaH */
