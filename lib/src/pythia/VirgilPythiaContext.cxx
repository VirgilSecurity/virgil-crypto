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

#include <virgil/crypto/pythia/VirgilPythiaContext.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

#include "mbedtls_context.h"
#include "utils.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <string>
#include <vector>
#include <iostream>

#include <mutex>
#include <thread>
#include <pythia/pythia.h>
#include <tinyformat/tinyformat.h>

using virgil::crypto::make_error;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::foundation::system_crypto_handler;
using virgil::crypto::foundation::internal::mbedtls_context;
using virgil::crypto::pythia::VirgilPythiaContext;

static thread_local mbedtls_context<mbedtls_entropy_context> g_entropy_ctx;
static thread_local mbedtls_context<mbedtls_ctr_drbg_context> g_rng_ctx;
static size_t g_instances;
static std::mutex g_instances_mutex;


static std::mutex messages_mutex;
static std::vector<std::string> messages;

static void append_message(const std::string& message) {
    // std::lock_guard<std::mutex> lock(messages_mutex);
    // messages.push_back(message);
}

static void purge_messages() {
    // std::lock_guard<std::mutex> lock(messages_mutex);
    // for (const auto& message : messages) {
    //     std::cout << message;
    // }
    // messages.clear();
}

static void random_handler(uint8_t *out, int out_len, void *) {

    // append_message(tfm::format("random_handler with ctx: %p, thread %lu\n", g_rng_ctx.get(), std::this_thread::get_id()));
    system_crypto_handler(mbedtls_ctr_drbg_random(g_rng_ctx.get(), out, out_len));
}

namespace internal {

class PythiaContext {
public:
    PythiaContext() {
        // append_message(tfm::format("PythiaContext CTOR from thread: %lu\n", std::this_thread::get_id()));

        constexpr const char pers[] = "VirgilPythiaContext";
        g_rng_ctx.setup(mbedtls_entropy_func, g_entropy_ctx.get(), pers);

        // append_message(tfm::format("Init RNG context: %p, thread %lu\n", g_rng_ctx.get(), std::this_thread::get_id()));

        std::lock_guard<std::mutex> lock_guard(g_instances_mutex);
        if (g_instances++ > 0) {
            return;
        }

        pythia_init_args_t init_args;
        init_args.callback = random_handler;
        init_args.args = NULL;

        system_crypto_handler(pythia_init(&init_args));
        // append_message(tfm::format("Pythia init from thread: %lu\n", std::this_thread::get_id()));
    }

    ~PythiaContext() noexcept {
        // append_message(tfm::format("PythiaContext DTOR from thread: %lu\n", std::this_thread::get_id()));

        std::lock_guard<std::mutex> lock_guard(g_instances_mutex);
        if (--g_instances > 0) {
            return;
        }
        pythia_deinit();
        // append_message(tfm::format("Pythia de-init from thread: %lu\n", std::this_thread::get_id()));

        purge_messages();
    }
};

}

VirgilPythiaContext::VirgilPythiaContext() {
    //  Need to call ctor and dtor on thread exit
    static thread_local internal::PythiaContext pythiaContext;
}

#endif /* VIRGIL_CRYPTO_FEATURE_PYTHIA */
