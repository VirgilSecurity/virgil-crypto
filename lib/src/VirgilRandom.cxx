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

#include <virgil/crypto/foundation/VirgilRandom.h>

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
    VirgilByteArray personalInfo;
    internal::mbedtls_context <mbedtls_ctr_drbg_context> ctr_drbg_ctx;
    internal::mbedtls_context <mbedtls_entropy_context> entropy_ctx;
};

VirgilRandom::VirgilRandom(const VirgilByteArray& personalInfo) : impl_(std::make_unique<Impl>()) {
    impl_->personalInfo = personalInfo;
    init();
}

VirgilRandom::VirgilRandom(const std::string& personalInfo) : impl_(std::make_unique<Impl>()) {
    impl_->personalInfo = VirgilByteArrayUtils::stringToBytes(personalInfo);
    init();
}

VirgilRandom::VirgilRandom(VirgilRandom&& rhs) noexcept = default;

VirgilRandom& VirgilRandom::operator=(VirgilRandom&& rhs) noexcept = default;

VirgilRandom::~VirgilRandom() noexcept = default;


VirgilRandom::VirgilRandom(const VirgilRandom& rhs) : impl_(std::make_unique<Impl>()) {
    impl_->personalInfo = rhs.impl_->personalInfo;
    init();
}

VirgilRandom& VirgilRandom::operator=(const VirgilRandom& rhs) {
    auto tmp = VirgilRandom(rhs);
    *this = std::move(tmp);
    return *this;
}

VirgilByteArray VirgilRandom::randomize(size_t bytesNum) {
    return internal::randomize(impl_->ctr_drbg_ctx, bytesNum);
}

size_t VirgilRandom::randomize() {
    return internal::randomize(impl_->ctr_drbg_ctx);
}

size_t VirgilRandom::randomize(size_t min, size_t max) {
    return internal::randomize(impl_->ctr_drbg_ctx, min, max);
}

void VirgilRandom::init() {
    impl_->ctr_drbg_ctx.setup(mbedtls_entropy_func, impl_->entropy_ctx.get(), impl_->personalInfo);
}
