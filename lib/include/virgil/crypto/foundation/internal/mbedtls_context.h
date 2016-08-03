/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#ifndef VIRGIL_CRYPTO_MBEDTLS_CONTEXT_H
#define VIRGIL_CRYPTO_MBEDTLS_CONTEXT_H

#include <memory>
#include <virgil/crypto/internal/utils.h>

namespace virgil { namespace crypto { namespace foundation { namespace internal {

template<typename T>
class mbedtls_context_policy;

template<typename T, typename Policy = mbedtls_context_policy<T>>
class mbedtls_context {
public:
    mbedtls_context() noexcept : ctx_(std::make_unique<T>()) {
        Policy::init_ctx(ctx_.get());
    }

    template<typename... Args>
    mbedtls_context(Args&& ...args) : ctx_(std::make_unique<T>()) {
        Policy::init_ctx(ctx_.get(), std::forward(args)...);
    }

    ~mbedtls_context() noexcept {
        Policy::free_ctx(ctx_.get());
    }

    mbedtls_context<T, Policy>& clear() {
        Policy::free_ctx(ctx_.get());
        ctx_ = std::make_unique<T>();
        Policy::init_ctx(ctx_.get());
        return *this;
    };

    template<typename... Args>
    void setup(Args ...args) {
        Policy::setup_ctx(ctx_.get(), args...);
    }

    T* get() noexcept { return ctx_.get(); }

    const T* get() const noexcept { return ctx_.get(); }

public:
    mbedtls_context(mbedtls_context&& rhs) = default;

    mbedtls_context& operator=(mbedtls_context&& rhs) = default;

private:
    std::unique_ptr<T> ctx_;
};

}}}}

#include "mbedtls_context_policy_spec.h"

#endif //VIRGIL_CRYPTO_MBEDTLS_CONTEXT_H
