/**
 * Copyright (C) 2014 Virgil Security Inc.
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
using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::VirgilRandomImpl;

#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include <virgil/crypto/VirgilByteArray.h>
using virgil::crypto::VirgilByteArray;

#include <virgil/crypto/foundation/PolarsslException.h>
using virgil::crypto::foundation::PolarsslException;

namespace virgil { namespace crypto { namespace foundation {

class VirgilRandomImpl {
public:
    ctr_drbg_context ctr_drbg;
    entropy_context entropy;
};

}}}

VirgilRandom::VirgilRandom(const VirgilByteArray& personalInfo) : impl_(new VirgilRandomImpl()) {
    entropy_init(&impl_->entropy);

    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::ctr_drbg_init(&impl_->ctr_drbg, entropy_func, &impl_->entropy,
                VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(personalInfo)),
        {
            ::entropy_free(&impl_->entropy);
            delete impl_;
        }
    );
}

VirgilByteArray VirgilRandom::randomize(size_t bytesNum) {
    unsigned char * buf = new unsigned char[bytesNum];

    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::ctr_drbg_random(&impl_->ctr_drbg, buf, bytesNum),
        {
            delete[] buf;
        }
    );

    VirgilByteArray randomBytes =  VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(buf, bytesNum);
    delete[] buf;
    return randomBytes;
}

VirgilRandom::~VirgilRandom() throw() {
    ::ctr_drbg_free(&impl_->ctr_drbg);
    ::entropy_free(&impl_->entropy);
    delete impl_;
}

