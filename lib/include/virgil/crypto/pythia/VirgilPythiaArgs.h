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

#ifndef VIRGIL_PYTHIA_ARGS_H
#define VIRGIL_PYTHIA_ARGS_H

#include "../VirgilByteArray.h"

namespace virgil {
namespace crypto {
namespace pythia {

class VirgilPythiaBlindResult {
public:
  explicit VirgilPythiaBlindResult(VirgilByteArray blindedPassword,
                                   VirgilByteArray blindingSecret)
      : blindedPassword_(std::move(blindedPassword)),
        blindingSecret_(std::move(blindingSecret)) {}

  const VirgilByteArray &blindedPassword() const { return blindedPassword_; }
  const VirgilByteArray &blindingSecret() const { return blindingSecret_; }

private:
  const VirgilByteArray blindedPassword_;
  const VirgilByteArray blindingSecret_;
};

class VirgilPythiaTransformResult {
public:
  explicit VirgilPythiaTransformResult(VirgilByteArray transformedPassword,
                                       VirgilByteArray transformationPrivateKey,
                                       VirgilByteArray transformedTweak)
      : transformedPassword_(std::move(transformedPassword)),
        transformationPrivateKey_(std::move(transformationPrivateKey)),
        transformedTweak_(std::move(transformedTweak)) {}

  const VirgilByteArray &transformedPassword() const {
    return transformedPassword_;
  }

  const VirgilByteArray &transformationPrivateKey() const {
    return transformationPrivateKey_;
  }

  const VirgilByteArray &transformedTweak() const { return transformedTweak_; }

private:
  const VirgilByteArray transformedPassword_;
  const VirgilByteArray transformationPrivateKey_;
  const VirgilByteArray transformedTweak_;
};

class VirgilPythiaDeblindResult {
public:
  explicit VirgilPythiaDeblindResult(VirgilByteArray deblindedPassword)
      : deblindedPassword_(std::move(deblindedPassword)) {}

  const VirgilByteArray deblindedPassword() const { return deblindedPassword_; }

private:
  const VirgilByteArray deblindedPassword_;
};

class VirgilPythiaProveResult {
public:
  explicit VirgilPythiaProveResult(VirgilByteArray transformationPublicKey,
                                   VirgilByteArray proofValueC,
                                   VirgilByteArray proofValueU)
      : transformationPublicKey_(std::move(transformationPublicKey)),
        proofValueC_(std::move(proofValueC)),
        proofValueU_(std::move(proofValueU)) {}

  const VirgilByteArray &transformationPublicKey() {
    return transformationPublicKey_;
  }

  const VirgilByteArray &proofValueC() { return proofValueC_; }
  const VirgilByteArray &proofValueU() { return proofValueU_; }

private:
  const VirgilByteArray transformationPublicKey_;
  const VirgilByteArray proofValueC_;
  const VirgilByteArray proofValueU_;
};

class VirgilPythiaGetPasswordUpdateTokenResult {
  explicit VirgilPythiaGetPasswordUpdateTokenResult(
      VirgilByteArray passwordUpdateToken,
      VirgilByteArray updatedTransformationPublicKey)
      : passwordUpdateToken_(std::move(passwordUpdateToken)),
        updatedTransformationPublicKey_(
            std::move(updatedTransformationPublicKey)) {}

public:
  const VirgilByteArray &passwordUpdateToken() const {
    return passwordUpdateToken_;
  }

  const VirgilByteArray &updatedTransformationPublicKey() const {
    return updatedTransformationPublicKey_;
  }

private:
  const VirgilByteArray passwordUpdateToken_;
  const VirgilByteArray updatedTransformationPublicKey_;
};

class VirgilPythiaVerifyResult {
  explicit VirgilPythiaVerifyResult(bool verified) : verified_(verified) {}

  bool verified() const { return verified_; }

private:
  bool verified_;
};

class VirgilPythiaUpdateDeblindedWithTokenResult {
public:
  explicit VirgilPythiaUpdateDeblindedWithTokenResult(
      VirgilByteArray updatedDeblindedPassword)
      : updatedDeblindedPassword_(std::move(updatedDeblindedPassword)) {}

  const VirgilByteArray &updatedDeblindedPassword() const {
    return updatedDeblindedPassword_;
  }

private:
  const VirgilByteArray updatedDeblindedPassword_;
};

} // namespace pythia
} // namespace crypto
} // namespace virgil

#endif /* VIRGIL_PYTHIA_ARGS_H */
