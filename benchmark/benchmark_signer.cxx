
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

/**
 * @file benchmark_signer.cxx
 * @brief Benchmark for encryption operations: sign and verify
 */

#define BENCHPRESS_CONFIG_MAIN
#include "benchpress.hpp"

#include <functional>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilSigner.h>

using std::placeholders::_1;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilSigner;

void benchmark_sign(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilByteArray testData = VirgilByteArrayUtils::stringToBytes("this string will be signed");
    VirgilKeyPair keyPair = VirgilKeyPair::generate(keyType);
    VirgilSigner signer;
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void)signer.sign(testData, keyPair.privateKey());
    }
}

void benchmark_verify(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilByteArray testData = VirgilByteArrayUtils::stringToBytes("this string will be verified");
    VirgilKeyPair keyPair = VirgilKeyPair::generate(keyType);
    VirgilSigner signer;
    VirgilByteArray sign = signer.sign(testData, keyPair.privateKey());
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void)signer.verify(testData, sign, keyPair.publicKey());
    }
}

BENCHMARK("Sign   -> curve25519         ", std::bind(benchmark_sign, _1, VirgilKeyPair::Type_EC_M255));
BENCHMARK("Sign   -> 224-bits NIST curve", std::bind(benchmark_sign, _1, VirgilKeyPair::Type_EC_SECP224R1));
BENCHMARK("Sign   -> 256-bits NIST curve", std::bind(benchmark_sign, _1, VirgilKeyPair::Type_EC_SECP256R1));
BENCHMARK("Sign   -> 384-bits NIST curve", std::bind(benchmark_sign, _1, VirgilKeyPair::Type_EC_SECP384R1));

BENCHMARK("Verify -> curve25519         ", std::bind(benchmark_verify, _1, VirgilKeyPair::Type_EC_M255));
BENCHMARK("Verify -> 224-bits NIST curve", std::bind(benchmark_verify, _1, VirgilKeyPair::Type_EC_SECP224R1));
BENCHMARK("Verify -> 256-bits NIST curve", std::bind(benchmark_verify, _1, VirgilKeyPair::Type_EC_SECP256R1));
BENCHMARK("Verify -> 384-bits NIST curve", std::bind(benchmark_verify, _1, VirgilKeyPair::Type_EC_SECP384R1));
