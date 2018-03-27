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

#include <virgil/crypto/VirgilPythiaContext.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

#include "utils.h"
#include "mbedtls_context.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <pythia/pythia.h>

using virgil::crypto::VirgilPythiaContext;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::make_error;
using virgil::crypto::foundation::system_crypto_handler;
using virgil::crypto::foundation::internal::mbedtls_context;


namespace virgil { namespace crypto { namespace internal {

class Context {
public:
    Context() {
        constexpr const char pers[] = "VirgilPythiaContext";
        ctr_drbg_ctx.setup(mbedtls_entropy_func, entropy_ctx.get(), pers);

        pythia_init_args_t rng_ctx;
        rng_ctx.callback = Context::random_handler;
        rng_ctx.args = &ctr_drbg_ctx;

        system_crypto_handler(
            pythia_init(&rng_ctx)
        );
    }

private:
    static void random_handler(uint8_t *out, int out_len, void *rng_ctx) {
        system_crypto_handler(
            mbedtls_ctr_drbg_random(rng_ctx, (unsigned char *)out, out_len)
        );
    }

private:
    mbedtls_context<mbedtls_entropy_context> entropy_ctx;
    mbedtls_context<mbedtls_ctr_drbg_context> ctr_drbg_ctx;
};

}}}


VirgilPythiaContext::VirgilPythiaContext() {
    static thread_local internal::Context context;
}

#endif /* VIRGIL_CRYPTO_FEATURE_PYTHIA */
