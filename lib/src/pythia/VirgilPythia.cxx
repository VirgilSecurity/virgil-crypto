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

#if VIRGIL_CRYPTO_FEATURE_PYTHIA

#include <virgil/crypto/pythia/VirgilPythia.h>

#include <virgil/crypto/pythia/VirgilPythiaError.h>

#include <pythia/pythia.h>

using virgil::crypto::make_error;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::pythia::pythia_handler;
using virgil::crypto::pythia::VirgilPythia;
using virgil::crypto::pythia::VirgilPythiaBlindResult;
using virgil::crypto::pythia::VirgilPythiaContext;
using virgil::crypto::pythia::VirgilPythiaDeblindResult;
using virgil::crypto::pythia::VirgilPythiaTransformationKeyPair;
using virgil::crypto::pythia::VirgilPythiaProveResult;
using virgil::crypto::pythia::VirgilPythiaTransformResult;
using virgil::crypto::pythia::VirgilPythiaVerifyResult;

class buffer_bind_out {
public:
    buffer_bind_out(VirgilByteArray& out) : buffer_(), out_(out) {
        buffer_.p = out.data();
        buffer_.allocated = out.capacity();
        buffer_.len = 0;
    }

    ~buffer_bind_out() noexcept {
        out_.resize(buffer_.len);
    }

    operator pythia_buf_t*() {
        return &buffer_;
    }

private:
    pythia_buf_t buffer_;
    VirgilByteArray& out_;
};

class buffer_bind_in {
public:
    buffer_bind_in(const VirgilByteArray& in) {
        buffer_.p = const_cast<uint8_t*>(in.data());
        buffer_.allocated = in.capacity();
        buffer_.len = in.size();
    }

    operator const pythia_buf_t*() const {
        return &buffer_;
    }

private:
    pythia_buf_t buffer_;
};

VirgilPythiaBlindResult VirgilPythia::blind(const VirgilByteArray& password) {
    VirgilByteArray blindedPassword(PYTHIA_G1_BUF_SIZE);
    VirgilByteArray blindingSecret(PYTHIA_BN_BUF_SIZE);

    pythia_handler(pythia_w_blind(
            buffer_bind_in(password), buffer_bind_out(blindedPassword),
            buffer_bind_out(blindingSecret)));

    return VirgilPythiaBlindResult(std::move(blindedPassword), std::move(blindingSecret));
}

VirgilPythiaDeblindResult VirgilPythia::deblind(
        const VirgilByteArray& transformedPassword, const VirgilByteArray& blindingSecret) {

    VirgilByteArray deblindedPassword(PYTHIA_GT_BUF_SIZE);

    pythia_handler(pythia_w_deblind(
            buffer_bind_in(transformedPassword), buffer_bind_in(blindingSecret),
            buffer_bind_out(deblindedPassword)));

    return VirgilPythiaDeblindResult(std::move(deblindedPassword));
}

VirgilPythiaTransformationKeyPair VirgilPythia::computeTransformationKeyPair(
        const virgil::crypto::VirgilByteArray &transformationKeyID, const virgil::crypto::VirgilByteArray &pythiaSecret,
        const virgil::crypto::VirgilByteArray &pythiaScopeSecret) {

    VirgilByteArray transformationPrivateKey(PYTHIA_BN_BUF_SIZE);
    VirgilByteArray transformationPublicKey(PYTHIA_G1_BUF_SIZE);

    pythia_handler(pythia_w_compute_transformation_key_pair(
            buffer_bind_in(transformationKeyID), buffer_bind_in(pythiaSecret), buffer_bind_in(pythiaScopeSecret),
            buffer_bind_out(transformationPrivateKey), buffer_bind_out(transformationPublicKey)));

    return VirgilPythiaTransformationKeyPair(
            std::move(transformationPrivateKey), std::move(transformationPublicKey));
}

VirgilPythiaTransformResult VirgilPythia::transform(
        const VirgilByteArray& blindedPassword,
        const VirgilByteArray& tweak, const VirgilByteArray& transformationPrivateKey) {

    VirgilByteArray transformedPassword(PYTHIA_GT_BUF_SIZE);
    VirgilByteArray transformedTweak(PYTHIA_G2_BUF_SIZE);

    pythia_handler(pythia_w_transform(
            buffer_bind_in(blindedPassword), buffer_bind_in(tweak), buffer_bind_in(transformationPrivateKey),
            buffer_bind_out(transformedPassword), buffer_bind_out(transformedTweak)));

    return VirgilPythiaTransformResult(
            std::move(transformedPassword), std::move(transformedTweak));
}

VirgilPythiaProveResult VirgilPythia::prove(
        const VirgilByteArray& transformedPassword, const VirgilByteArray& blindedPassword,
        const VirgilByteArray& transformedTweak, const VirgilByteArray& transformationPrivateKey,
        const VirgilByteArray& transformationPublicKey) {

    VirgilByteArray proofValueC(PYTHIA_BN_BUF_SIZE);
    VirgilByteArray proofValueU(PYTHIA_BN_BUF_SIZE);

    pythia_handler(pythia_w_prove(
            buffer_bind_in(transformedPassword), buffer_bind_in(blindedPassword),
            buffer_bind_in(transformedTweak), buffer_bind_in(transformationPrivateKey),
            buffer_bind_in(transformationPublicKey), buffer_bind_out(proofValueC),
            buffer_bind_out(proofValueU)));

    return VirgilPythiaProveResult(std::move(proofValueC), std::move(proofValueU));
}

VirgilPythiaVerifyResult VirgilPythia::verify(
        const VirgilByteArray& transformedPassword, const VirgilByteArray& blindedPassword,
        const VirgilByteArray& tweak, const VirgilByteArray& transformationPublicKey,
        const VirgilByteArray& proofValueC, const VirgilByteArray& proofValueU) {

    int verified = 0;

    pythia_handler(pythia_w_verify(
            buffer_bind_in(transformedPassword), buffer_bind_in(blindedPassword),
            buffer_bind_in(tweak), buffer_bind_in(transformationPublicKey),
            buffer_bind_in(proofValueC), buffer_bind_in(proofValueU), &verified));

    return VirgilPythiaVerifyResult(verified != 0);
}

VirgilByteArray VirgilPythia::getPasswordUpdateToken(
        const VirgilByteArray& previousTransformationPrivateKey,
        const VirgilByteArray& newTransformationPrivateKey) {

    VirgilByteArray passwordUpdateToken(PYTHIA_BN_BUF_SIZE);

    pythia_handler(pythia_w_get_password_update_token(
            buffer_bind_in(previousTransformationPrivateKey), buffer_bind_in(newTransformationPrivateKey),
            buffer_bind_out(passwordUpdateToken)));

    return VirgilByteArray(std::move(passwordUpdateToken));
}

VirgilByteArray VirgilPythia::updateDeblindedWithToken(
        const VirgilByteArray& deblindedPassword, const VirgilByteArray& passwordUpdateToken) {

    VirgilByteArray updatedDeblindedPassword(PYTHIA_GT_BUF_SIZE);

    pythia_handler(pythia_w_update_deblinded_with_token(
            buffer_bind_in(deblindedPassword), buffer_bind_in(passwordUpdateToken),
            buffer_bind_out(updatedDeblindedPassword)));

    return VirgilByteArray(std::move(updatedDeblindedPassword));
}

#endif /* VIRGIL_CRYPTO_FEATURE_PYTHIA */
