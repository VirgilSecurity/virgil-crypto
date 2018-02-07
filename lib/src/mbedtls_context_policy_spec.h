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

#ifndef VIRGIL_CRYPTO_MBEDTLS_CONTEXT_POLICY_SPEC_H
#define VIRGIL_CRYPTO_MBEDTLS_CONTEXT_POLICY_SPEC_H

#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/cipher.h>

#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include "mbedtls_type_utils.h"

#include <array>

namespace virgil { namespace crypto { namespace foundation { namespace internal {

template<>
class mbedtls_context_policy<mbedtls_pk_context> {
    using context_type = mbedtls_pk_context;
    using info_type = mbedtls_pk_info_t;
public:
    static void init_ctx(context_type* ctx) {
        mbedtls_pk_init(ctx);
    }

    static void free_ctx(context_type* ctx) {
        mbedtls_pk_free(ctx);
    }

    template<typename Type>
    static void setup_ctx(context_type* ctx, Type type) {
        const info_type* info = mbedtls_pk_info_from_type(type);
        if (info == NULL) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(type));
        }
        system_crypto_handler(
                mbedtls_pk_setup(ctx, info),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );
    }
};

template<>
class mbedtls_context_policy<mbedtls_ctr_drbg_context> {
    using context_type = mbedtls_ctr_drbg_context;
public:
    static void init_ctx(context_type* ctx) {
        mbedtls_ctr_drbg_init(ctx);
    }

    static void free_ctx(context_type* ctx) {
        mbedtls_ctr_drbg_free(ctx);
    }

    template<typename EntropyFunc, typename EntropyContext>
    static void
    setup_ctx(context_type* ctx, EntropyFunc entropy_func, EntropyContext entropy_ctx, const std::string& pers) {
        system_crypto_handler(
                mbedtls_ctr_drbg_seed(ctx, entropy_func, entropy_ctx,
                        reinterpret_cast<const unsigned char*>(pers.data()), pers.size()),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
    }

    template<typename EntropyFunc, typename EntropyContext>
    static void
    setup_ctx(
            context_type* ctx, EntropyFunc entropy_func, EntropyContext entropy_ctx,
            const virgil::crypto::VirgilByteArray& pers) {
        system_crypto_handler(
                mbedtls_ctr_drbg_seed(ctx, entropy_func, entropy_ctx,
                        reinterpret_cast<const unsigned char*>(pers.data()), pers.size()),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::UnsupportedAlgorithm)); }
        );
    }
};

template<>
class mbedtls_context_policy<mbedtls_entropy_context> {
    using context_type = mbedtls_entropy_context;
public:
    static void init_ctx(context_type* ctx) {
        mbedtls_entropy_init(ctx);
    }

    static void free_ctx(context_type* ctx) {
        mbedtls_entropy_free(ctx);
    }
};

template<>
class mbedtls_context_policy<mbedtls_ecdh_context> {
    using context_type = mbedtls_ecdh_context;
public:
    static void init_ctx(context_type* ctx) {
        mbedtls_ecdh_init(ctx);
    }

    static void free_ctx(context_type* ctx) {
        mbedtls_ecdh_free(ctx);
    }
};

template<>
class mbedtls_context_policy<mbedtls_mpi> {
    using context_type = mbedtls_mpi;
public:
    static void init_ctx(context_type* ctx) {
        mbedtls_mpi_init(ctx);
    }

    static void free_ctx(context_type* ctx) {
        mbedtls_mpi_free(ctx);
    }
};

template<>
class mbedtls_context_policy<mbedtls_md_context_t> {
    using context_type = mbedtls_md_context_t;
    using info_type = mbedtls_md_info_t;
public:
    static void init_ctx(context_type* ctx) {
        mbedtls_md_init(ctx);
    }

    static void free_ctx(context_type* ctx) {
        mbedtls_md_free(ctx);
    }

    template<typename Type, typename... Args>
    static void setup_ctx(context_type* ctx, Type type, Args ...args) {
        const info_type* info = mbedtls_md_info_from_type(type);
        if (info == NULL) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(type));
        }
        system_crypto_handler(
                mbedtls_md_setup(ctx, info, args...),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );
    }

    template<typename... Args>
    static void setup_ctx(context_type* ctx, const char* name, Args ...args) {
        const info_type* info = mbedtls_md_info_from_string(name);
        if (info == NULL) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, name);
        }
        system_crypto_handler(
                mbedtls_md_setup(ctx, info, args...),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );
    }
};

template<>
class mbedtls_context_policy<mbedtls_cipher_context_t> {
    using context_type = mbedtls_cipher_context_t;
    using info_type = mbedtls_cipher_info_t;
public:
    static void init_ctx(context_type* ctx) {
        mbedtls_cipher_init(ctx);
    }

    static void free_ctx(context_type* ctx) {
        mbedtls_cipher_free(ctx);
    }

    template<typename Type>
    static void setup_ctx(context_type* ctx, Type type) {
        const info_type* info = mbedtls_cipher_info_from_type(type);
        if (info == NULL) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, internal::to_string(type));
        }
        system_crypto_handler(
                mbedtls_cipher_setup(ctx, info),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );
    }

    static void setup_ctx(context_type* ctx, const char* name) {
        const info_type* info = mbedtls_cipher_info_from_string(name);
        if (info == NULL) {
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, name);
        }
        system_crypto_handler(
                mbedtls_cipher_setup(ctx, info),
                [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidArgument)); }
        );
    }
};

inline VirgilByteArray randomize(mbedtls_context<mbedtls_ctr_drbg_context>& ctr_drbg_ctx, size_t bytesNum) {
    std::array<unsigned char, MBEDTLS_CTR_DRBG_MAX_REQUEST> buf;

    VirgilByteArray randomBytes;
    randomBytes.reserve(bytesNum);
    while (randomBytes.size() < bytesNum) {
        const size_t randomChunkSize = std::min(bytesNum, (size_t) MBEDTLS_CTR_DRBG_MAX_REQUEST);
        system_crypto_handler(
                mbedtls_ctr_drbg_random(ctr_drbg_ctx.get(), buf.data(), randomChunkSize));
        randomBytes.insert(randomBytes.end(), buf.begin(), buf.begin() + randomChunkSize);
    }
    return randomBytes;
};

inline size_t randomize(mbedtls_context<mbedtls_ctr_drbg_context>& ctr_drbg_ctx) {
    VirgilByteArray randomBytes = randomize(ctr_drbg_ctx, sizeof(size_t));
    return *((size_t*) &randomBytes[0]);
}

inline size_t randomize(mbedtls_context<mbedtls_ctr_drbg_context>& ctr_drbg_ctx, size_t min, size_t max) {
    if (min >= max) {
        throw make_error(VirgilCryptoError::InvalidArgument, "MIN value is greater or equal to MAX.");
    }
    return min + (randomize(ctr_drbg_ctx) % size_t(max - min));
}

}}}}

#endif //VIRGIL_CRYPTO_MBEDTLS_CONTEXT_POLICY_SPEC_H
