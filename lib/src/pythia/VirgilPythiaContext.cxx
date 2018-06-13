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

#include <virgil/crypto/pythia/VirgilPythiaError.h>

#include "mbedtls_context.h"
#include "utils.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <iostream>
#include <string>
#include <vector>

#include <mutex>
#include <pythia/pythia.h>
#include <thread>
#include <tinyformat/tinyformat.h>

#include <iostream>
#include <chrono>
#include <ctime>
#include <sstream>

using virgil::crypto::make_error;
using virgil::crypto::foundation::internal::mbedtls_context;
using virgil::crypto::pythia::pythia_handler;
using virgil::crypto::pythia::VirgilPythiaContext;

#if VIRGIL_CRYPTO_FEATURE_PYTHIA_MT
#   define VIRGIL_THREAD_LOCAL thread_local
#else
#   define VIRGIL_THREAD_LOCAL
#endif


static VIRGIL_THREAD_LOCAL mbedtls_context<mbedtls_entropy_context> g_entropy_ctx;
static VIRGIL_THREAD_LOCAL mbedtls_context<mbedtls_ctr_drbg_context> g_rng_ctx;
static size_t g_instances;
static std::mutex g_instances_mutex;

static void random_handler(uint8_t* out, int out_len, void*) {
    pythia_handler(mbedtls_ctr_drbg_random(g_rng_ctx.get(), out, out_len));
}

static std::string get_time() {
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();

    typedef std::chrono::duration<int, std::ratio_multiply<std::chrono::hours::period, std::ratio<8>>::type> Days; /* UTC: +8:00 */

    Days days = std::chrono::duration_cast<Days>(duration);
    duration -= days;
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    duration -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
    duration -= minutes;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    duration -= seconds;
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    duration -= milliseconds;
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
    duration -= microseconds;
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);

    std::ostringstream sstream;
    sstream   << std::setw(2) << std::setfill('0')<< hours.count() << ":"
              << std::setw(2) << std::setfill('0')<< minutes.count() << ":"
              << std::setw(2) << std::setfill('0')<< seconds.count() << ":"
              << std::setw(3) << std::setfill('0')<< milliseconds.count() << ":"
              << std::setw(3) << std::setfill('0')<< microseconds.count();
    return sstream.str();
}

namespace internal {

class PythiaContext {
public:
    PythiaContext() {
        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - started" << std::endl;
        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - before RNG init" << std::endl;
        constexpr const char pers[] = "VirgilPythiaContext";
        g_rng_ctx.setup(mbedtls_entropy_func, g_entropy_ctx.get(), pers);
        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - after RNG init" << std::endl;

        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - before lock" << std::endl;
        std::lock_guard<std::mutex> lock_guard(g_instances_mutex);
        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - after lock" << std::endl;
        if (g_instances++ > 0) {
            std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - g_instances > 0" << std::endl;
            return;
        }

        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - before global pythia init MUST be ONCE" << std::endl;

        pythia_init_args_t init_args;
        init_args.callback = random_handler;
        init_args.args = NULL;

        pythia_handler(pythia_init(&init_args));

        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::PythiaContext() - after global pythia init MUST be ONCE" << std::endl;
    }

    ~PythiaContext() noexcept {
        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::~PythiaContext() - before lock" << std::endl;
        std::lock_guard<std::mutex> lock_guard(g_instances_mutex);
        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::~PythiaContext() - after lock" << std::endl;
        if (--g_instances > 0) {
            std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::~PythiaContext() - g_instances > 0" << std::endl;
            return;
        }

        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::~PythiaContext() - before global pythia deinit MUST be ONCE" << std::endl;
        pythia_deinit();
        std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": PythiaContext::~PythiaContext() - after global pythia deinit MUST be ONCE" << std::endl;
    }
};

} // namespace internal

VirgilPythiaContext::VirgilPythiaContext() {
    std::cout << get_time() << "  :  Thread " << std::this_thread::get_id() << ": VirgilPythiaContext::VirgilPythiaContext() - started" << std::endl;
    //  Need to call ctor on a thread creation and dtor on thread exit
    static VIRGIL_THREAD_LOCAL internal::PythiaContext pythiaContext;
}

#endif /* VIRGIL_CRYPTO_FEATURE_PYTHIA */
