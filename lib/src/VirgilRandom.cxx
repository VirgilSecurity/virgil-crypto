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

#include <virgil/crypto/foundation/VirgilRandom.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform.h>
#include <tinyformat/tinyformat.h>


#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/VirgilCryptoException.h>

#include "utils.h"
#include "mbedtls_context.h"


#if VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE
#include <fstream>
#include <mutex>
#endif


using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;

using virgil::crypto::VirgilCryptoError;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::make_error;

using virgil::crypto::foundation::VirgilRandom;


#if VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE
static std::string g_seedFilePath_;
static std::mutex g_seedFileMutex_;

static int seed_file_read(unsigned char *buf, size_t buf_len) {
    std::lock_guard<std::mutex> guard(g_seedFileMutex_);

    std::ifstream in(g_seedFilePath_.c_str(), std::ifstream::binary);

    if (in.read((char *)buf, buf_len)) {
        return 0;
    }

    return -1;
}

static int seed_file_write(unsigned char *buf, size_t buf_len) {
    std::lock_guard<std::mutex> guard(g_seedFileMutex_);

    std::ofstream out(g_seedFilePath_.c_str(), std::ifstream::binary);

    if (out.write((char *)buf, buf_len)) {
        return 0;
    }

    return -1;
}
#endif /* VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE */

void VirgilRandom::setSeedFile(std::string path) {
#if VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE
    if (path.empty()) {
        throw make_error(VirgilCryptoError::EmptyParameter);
    }

    std::ifstream seedFile(path.c_str(), std::ifstream::binary);
    if(!seedFile) {
        throw make_error(VirgilCryptoError::FileNotFound, tfm::format("Can not open file at path: %s.", path));
    }

    seedFile.seekg(0, seedFile.end);
    auto seedFileLength = !seedFile.fail() ? seedFile.tellg() : std::streampos(0);

    if (seedFileLength < MBEDTLS_ENTROPY_BLOCK_SIZE) {
        throw make_error(VirgilCryptoError::FileTooSmall,
                tfm::format("Expected '%s' file size at least %d bytes, available %d bytes.",
                        path, MBEDTLS_ENTROPY_BLOCK_SIZE, seedFileLength));
    }

    g_seedFilePath_ = std::move(path);

    (void)mbedtls_platform_set_nv_seed(seed_file_read, seed_file_write);
#else
    (void)path;
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
#endif
}

size_t VirgilRandom::seedFileLengthMin() {
#if VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE
    return MBEDTLS_ENTROPY_BLOCK_SIZE;
#else
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
#endif
}


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
