/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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
 * @file benchmark_cipher.cxx
 * @brief Benchmark for encryption operations: encrypt and decrypt
 */

#define BENCHPRESS_CONFIG_MAIN

#include "benchpress.hpp"

#include <functional>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

using std::placeholders::_1;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::foundation::VirgilAsymmetricCipher;

void benchmark_keys_keygen(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilAsymmetricCipher asymmetricCipher;
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        asymmetricCipher.genKeyPair(keyType);
    }
}

void benchmark_keys_public_export_pem(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilAsymmetricCipher asymmetricCipher;
    asymmetricCipher.genKeyPair(keyType);
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) asymmetricCipher.exportPublicKeyToPEM();
    }
}

void benchmark_keys_public_export_der(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilAsymmetricCipher asymmetricCipher;
    asymmetricCipher.genKeyPair(keyType);
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) asymmetricCipher.exportPublicKeyToDER();
    }
}

void benchmark_keys_private_export_pem_no_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilAsymmetricCipher asymmetricCipher;
    asymmetricCipher.genKeyPair(keyType);
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) asymmetricCipher.exportPrivateKeyToPEM();
    }
}

void benchmark_keys_private_export_der_no_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilAsymmetricCipher asymmetricCipher;
    asymmetricCipher.genKeyPair(keyType);
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) asymmetricCipher.exportPrivateKeyToDER();
    }
}

void benchmark_keys_private_export_pem_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilAsymmetricCipher asymmetricCipher;
    asymmetricCipher.genKeyPair(keyType);
    auto pwd = VirgilByteArrayUtils::stringToBytes("pwd");
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) asymmetricCipher.exportPrivateKeyToPEM(pwd);
    }
}

void benchmark_keys_private_export_der_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    VirgilAsymmetricCipher asymmetricCipher;
    asymmetricCipher.genKeyPair(keyType);
    auto pwd = VirgilByteArrayUtils::stringToBytes("pwd");
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) asymmetricCipher.exportPrivateKeyToDER(pwd);
    }
}

void benchmark_keys_public_export_der2pem(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    auto keyPair = VirgilKeyPair::generate(keyType);
    auto publicKey = VirgilKeyPair::publicKeyToDER(keyPair.publicKey());
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) VirgilKeyPair::publicKeyToPEM(publicKey);
    }
}

void benchmark_keys_public_export_pem2der(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    auto keyPair = VirgilKeyPair::generate(keyType);
    auto publicKey = VirgilKeyPair::publicKeyToPEM(keyPair.publicKey());
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) VirgilKeyPair::publicKeyToDER(publicKey);
    }
}

void benchmark_keys_private_export_der2pem_no_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    auto keyPair = VirgilKeyPair::generate(keyType);
    auto privateKey = VirgilKeyPair::privateKeyToDER(keyPair.privateKey());
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) VirgilKeyPair::privateKeyToPEM(privateKey);
    }
}

void benchmark_keys_private_export_pem2der_no_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    auto keyPair = VirgilKeyPair::generate(keyType);
    auto privateKey = VirgilKeyPair::privateKeyToPEM(keyPair.privateKey());
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) VirgilKeyPair::privateKeyToDER(privateKey);
    }
}

void benchmark_keys_private_export_der2pem_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    auto pwd = VirgilByteArrayUtils::stringToBytes("pwd");
    auto keyPair = VirgilKeyPair::generate(keyType, pwd);
    auto privateKey = VirgilKeyPair::privateKeyToDER(keyPair.privateKey(), pwd);
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) VirgilKeyPair::privateKeyToPEM(privateKey, pwd);
    }
}

void benchmark_keys_private_export_pem2der_pwd(benchpress::context* ctx, const VirgilKeyPair::Type& keyType) {
    auto pwd = VirgilByteArrayUtils::stringToBytes("pwd");
    auto keyPair = VirgilKeyPair::generate(keyType, pwd);
    auto privateKey = VirgilKeyPair::privateKeyToPEM(keyPair.privateKey(), pwd);
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        (void) VirgilKeyPair::privateKeyToDER(privateKey, pwd);
    }
}


BENCHMARK("Generate key pair -> curve25519              ",
          std::bind(benchmark_keys_keygen, _1, VirgilKeyPair::Type::FAST_EC_X25519));
BENCHMARK("Generate key pair -> ed25519                 ",
          std::bind(benchmark_keys_keygen, _1, VirgilKeyPair::Type::FAST_EC_ED25519));
BENCHMARK("Generate key pair -> 224-bits NIST curve     ",
          std::bind(benchmark_keys_keygen, _1, VirgilKeyPair::Type::EC_SECP224R1));
BENCHMARK("Generate key pair -> 256-bits NIST curve     ",
          std::bind(benchmark_keys_keygen, _1, VirgilKeyPair::Type::EC_SECP256R1));
BENCHMARK("Generate key pair -> 384-bits NIST curve     ",
          std::bind(benchmark_keys_keygen, _1, VirgilKeyPair::Type::EC_SECP384R1));

BENCHMARK("Export Public Key to DER                     ",
          std::bind(benchmark_keys_public_export_der, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Public Key to PEM                     ",
          std::bind(benchmark_keys_public_export_pem, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key to DER (no password)      ",
          std::bind(benchmark_keys_private_export_der_no_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key to PEM (no password)      ",
          std::bind(benchmark_keys_private_export_pem_no_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key to DER (with password)    ",
          std::bind(benchmark_keys_private_export_der_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key to PEM (with password)    ",
          std::bind(benchmark_keys_private_export_pem_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Public Key DER to PEM                 ",
          std::bind(benchmark_keys_public_export_der2pem, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Public Key PEM to DER                 ",
          std::bind(benchmark_keys_public_export_pem2der, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key PEM to DER (no password)  ",
          std::bind(benchmark_keys_private_export_der2pem_no_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key DER to PEM (no password)  ",
          std::bind(benchmark_keys_private_export_pem2der_no_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key DER to PEM (with password)",
          std::bind(benchmark_keys_private_export_der2pem_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));

BENCHMARK("Export Private Key PEM to DER (with password)",
          std::bind(benchmark_keys_private_export_pem2der_pwd, _1, VirgilKeyPair::Type::FAST_EC_ED25519));
