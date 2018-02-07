
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

/**
 * @file benchmark_cipher.cxx
 * @brief Benchmark for encryption operations: encrypt and decrypt
 */

#define BENCHPRESS_CONFIG_MAIN
#include "benchpress.hpp"

#include <functional>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilRandom.h>

using std::placeholders::_1;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::VirgilRandom;

void benchmark_hash(benchpress::context* ctx, VirgilHash::Algorithm hashAlg) {
    VirgilRandom random(VirgilByteArrayUtils::stringToBytes("seed"));
    VirgilByteArray testData = random.randomize(8192);
    VirgilHash hash(hashAlg);
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void)hash.hash(testData);
    }
}

BENCHMARK("Hash -> MD5    ", [](benchpress::context* ctx){
    benchmark_hash(ctx, VirgilHash::Algorithm::MD5);
});

BENCHMARK("Hash -> SHA-256", [](benchpress::context* ctx){
    benchmark_hash(ctx, VirgilHash::Algorithm::SHA256);
});

BENCHMARK("Hash -> SHA-384", [](benchpress::context* ctx){
    benchmark_hash(ctx, VirgilHash::Algorithm::SHA384);
});

BENCHMARK("Hash -> SHA-512", [](benchpress::context* ctx){
    benchmark_hash(ctx, VirgilHash::Algorithm::SHA512);
});

