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

#ifndef VIRGIL_PYTHIA_H
#define VIRGIL_PYTHIA_H

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
 *  PYTHIA is a verifiable, cryptographic protocol that hardens passwords
 *  with the help of a remote service.
 *
 *  This module contains
 */
class VirgilPythia {
public:
    VirgilPythiaBlindResult blind(const VirgilByteArray& password);

    VirgilPythiaTransformResult transform(const VirgilByteArray& blindedPassword,
            const VirgilByteArray& transformationKeyID, const VirgilByteArray& tweak,
            const VirgilByteArray& pythiaSecret, const VirgilByteArray& pythiaScopeSecret);

    VirgilPythiaDeblindResult deblind(
            const VirgilByteArray& transformedPassword, const VirgilByteArray& blindingSecret);

    VirgilPythiaProveResult prove(const VirgilByteArray& transformedPassword,
            const VirgilByteArray& blindedPassword, const VirgilByteArray& transformedTweak,
            const VirgilByteArray& transformationPrivateKey);

    VirgilPythiaVerifyResult verify(const VirgilByteArray& transformedPassword,
            const VirgilByteArray& blindedPassword, const VirgilByteArray& tweak,
            const VirgilByteArray& transformationPublicKey, const VirgilByteArray& proofValueC,
            const VirgilByteArray& proofValueU);

    VirgilPythiaGetPasswordUpdateTokenResult getPasswordUpdateToken(
            const VirgilByteArray& previousTransformationKeyID,
            const VirgilByteArray& previousPythiaSecret,
            const VirgilByteArray& previousPythiaScopeSecret,
            const VirgilByteArray& newTransformationKeyID, const VirgilByteArray& newPythiaSecret,
            const VirgilByteArray& newPythiaScopeSecret);

    VirgilPythiaUpdateDeblindedWithTokenResult updateDeblindedWithToken(
            const VirgilByteArray& deblindedPassword, const VirgilByteArray& passwordUpdateToken);

private:
    VirgilPythiaContext pythiaContext;
};

} // namespace pythia
} // namespace crypto
} // namespace virgil

#endif /* VIRGIL_PYTHIA_H */
