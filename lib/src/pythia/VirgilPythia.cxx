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

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

#include <pythia/pythia.h>

using virgil::crypto::make_error;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::foundation::system_crypto_handler;
using virgil::crypto::pythia::VirgilPythia;
using virgil::crypto::pythia::VirgilPythiaBlindResult;
using virgil::crypto::pythia::VirgilPythiaContext;
using virgil::crypto::pythia::VirgilPythiaDeblindResult;
using virgil::crypto::pythia::VirgilPythiaGetPasswordUpdateTokenResult;
using virgil::crypto::pythia::VirgilPythiaProveResult;
using virgil::crypto::pythia::VirgilPythiaTransformResult;
using virgil::crypto::pythia::VirgilPythiaUpdateDeblindedWithTokenResult;
using virgil::crypto::pythia::VirgilPythiaVerifyResult;

static constexpr size_t kPythia_BufferSize = 512;

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
    VirgilByteArray blindedPassword(kPythia_BufferSize);
    VirgilByteArray blindingSecret(kPythia_BufferSize);

    VirgilPythiaIn passwordIn(password);

    system_crypto_handler(pythia_w_blind(
            buffer_bind_in(password), buffer_bind_out(blindedPassword),
            buffer_bind_out(blindingSecret)));

    return VirgilPythiaBlindResult(std::move(blindedPassword), std::move(blindingSecret));
}

VirgilPythiaTransformResult VirgilPythia::transform(
        const VirgilByteArray& blindedPassword, const VirgilByteArray& transformationKeyID,
        const VirgilByteArray& tweak, const VirgilByteArray& pythiaSecret,
        const VirgilByteArray& pythiaScopeSecret) { // pythia_w_transform();
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
}

VirgilPythiaDeblindResult VirgilPythia::deblind(
        const VirgilByteArray& transformedPassword,
        const VirgilByteArray& blindingSecret) { // pythia_w_deblind();
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
}

VirgilPythiaProveResult VirgilPythia::prove(
        const VirgilByteArray& transformedPassword, const VirgilByteArray& blindedPassword,
        const VirgilByteArray& transformedTweak,
        const VirgilByteArray& transformationPrivateKey) { // pythia_w_prove();
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
}

VirgilPythiaVerifyResult VirgilPythia::verify(
        const VirgilByteArray& transformedPassword, const VirgilByteArray& blindedPassword,
        const VirgilByteArray& tweak, const VirgilByteArray& transformationPublicKey,
        const VirgilByteArray& proofValueC,
        const VirgilByteArray& proofValueU) { // pythia_w_verify();
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
}

VirgilPythiaGetPasswordUpdateTokenResult VirgilPythia::getPasswordUpdateToken(
        const VirgilByteArray& previousTransformationKeyID,
        const VirgilByteArray& previousPythiaSecret,
        const VirgilByteArray& previousPythiaScopeSecret,
        const VirgilByteArray& newTransformationKeyID, const VirgilByteArray& newPythiaSecret,
        const VirgilByteArray& newPythiaScopeSecret) {
    // pythia_w_get_password_update_token();
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
}

VirgilPythiaUpdateDeblindedWithTokenResult VirgilPythia::updateDeblindedWithToken(
        const VirgilByteArray& deblindedPassword, const VirgilByteArray& passwordUpdateToken) {
    // pythia_w_update_deblinded_with_token();
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
}

#endif /* VIRGIL_CRYPTO_FEATURE_PYTHIA */
