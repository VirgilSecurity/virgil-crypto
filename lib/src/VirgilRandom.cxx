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

#define MODULE_NAME "VirgilRandom"

#include <virgil/crypto/foundation/VirgilRandom.h>

#include <array>
#include <atomic>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

#include <virgil/crypto/internal/utils.h>
#include <virgil/crypto/foundation/internal/mbedtls_context.h>


using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;

using virgil::crypto::foundation::VirgilRandom;

class VirgilRandom::Impl {
public:
    std::atomic<bool> is_init{ false };
    VirgilByteArray personalInfo;
    internal::mbedtls_context <mbedtls_ctr_drbg_context> ctr_drbg_ctx;
    internal::mbedtls_context <mbedtls_entropy_context> entropy_ctx;
};

VirgilRandom::VirgilRandom(const VirgilByteArray& personalInfo) : impl_(std::make_unique<Impl>()) {
    impl_->personalInfo = personalInfo;
}

VirgilRandom::VirgilRandom(const std::string& personalInfo) : impl_(std::make_unique<Impl>()) {
    impl_->personalInfo = VirgilByteArrayUtils::stringToBytes(personalInfo);
}

VirgilRandom::VirgilRandom(VirgilRandom&& rhs) noexcept = default;

VirgilRandom& VirgilRandom::operator=(VirgilRandom&& rhs) noexcept = default;

VirgilRandom::~VirgilRandom() noexcept = default;

VirgilByteArray VirgilRandom::randomize(size_t bytesNum) {

    if (!impl_->is_init) {
        impl_->ctr_drbg_ctx.setup(mbedtls_entropy_func, impl_->entropy_ctx.get(), impl_->personalInfo);
        VirgilByteArrayUtils::zeroize(impl_->personalInfo);
        impl_->personalInfo.clear();
        impl_->is_init = true;
    }

    std::array<unsigned char, MBEDTLS_CTR_DRBG_MAX_REQUEST> buf;

    VirgilByteArray randomBytes;
    randomBytes.reserve(bytesNum);
    while (randomBytes.size() < bytesNum) {
        const size_t randomChunkSize = std::min(bytesNum, (size_t) MBEDTLS_CTR_DRBG_MAX_REQUEST);
        system_crypto_handler(
                mbedtls_ctr_drbg_random(impl_->ctr_drbg_ctx.get(), buf.data(), randomChunkSize)
        );
        randomBytes.insert(randomBytes.end(), buf.begin(), buf.begin() + randomChunkSize);
    }
    return randomBytes;
}

size_t VirgilRandom::randomize() {
    VirgilByteArray randomBytes = randomize(sizeof(size_t));
    return *((size_t*) &randomBytes[0]);
}

size_t VirgilRandom::randomize(size_t min, size_t max) {
    if (min >= max) {
        throw make_error(VirgilCryptoError::InvalidArgument, "MIN value is greater or equal to MAX.");
    }
    return min + (randomize() % size_t(max - min));
}
