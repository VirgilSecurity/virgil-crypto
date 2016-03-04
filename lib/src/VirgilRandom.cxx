/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#include <algorithm>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/PolarsslException.h>


using virgil::crypto::VirgilByteArray;

using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::VirgilRandomImpl;
using virgil::crypto::foundation::PolarsslException;

namespace virgil { namespace crypto { namespace foundation {

class VirgilRandomImpl {
public:
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
};

}}}

VirgilRandom::VirgilRandom(const VirgilByteArray& personalInfo) : impl_(new VirgilRandomImpl()) {
    mbedtls_entropy_init(&impl_->entropy);

    ::mbedtls_ctr_drbg_init(&impl_->ctr_drbg);
    MBEDTLS_ERROR_HANDLER_DISPOSE(
        ::mbedtls_ctr_drbg_seed(&impl_->ctr_drbg, mbedtls_entropy_func, &impl_->entropy,
                VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(personalInfo)),
        {
            ::mbedtls_entropy_free(&impl_->entropy);
            delete impl_;
        }
    );
}

VirgilByteArray VirgilRandom::randomize(size_t bytesNum) {
    unsigned char buf[MBEDTLS_CTR_DRBG_MAX_REQUEST] = {0x0};

    VirgilByteArray randomBytes;
    randomBytes.reserve(bytesNum);
    while (randomBytes.size() < bytesNum) {
        const size_t randomChunkSize = std::min(bytesNum, (size_t)MBEDTLS_CTR_DRBG_MAX_REQUEST);
        MBEDTLS_ERROR_HANDLER(
            ::mbedtls_ctr_drbg_random(&impl_->ctr_drbg, buf, randomChunkSize)
        );
        randomBytes.insert(randomBytes.end(), buf, buf + randomChunkSize);
    }
    return randomBytes;
}

size_t VirgilRandom::randomize() {
    VirgilByteArray randomBytes = randomize(sizeof(size_t));
    return *((size_t *)&randomBytes[0]);
}

size_t VirgilRandom::randomize(size_t min, size_t max) {
    if (min > max) {
        throw std::logic_error("VirgilRandom: wrong range - min is greater than max");
    }
    return min + (randomize() % size_t(max - min));
}

VirgilRandom::~VirgilRandom() throw() {
    ::mbedtls_ctr_drbg_free(&impl_->ctr_drbg);
    ::mbedtls_entropy_free(&impl_->entropy);
    delete impl_;
}
