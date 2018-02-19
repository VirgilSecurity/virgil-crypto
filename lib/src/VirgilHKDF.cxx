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

#include <virgil/crypto/foundation/VirgilHKDF.h>

#include <virgil/crypto/VirgilCryptoError.h>

#include <cassert>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::make_error;
using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::VirgilHKDF;

VirgilHKDF::VirgilHKDF(VirgilHash::Algorithm hashAlgorithm) : hashAlgorithm_(hashAlgorithm) {}

VirgilByteArray VirgilHKDF::derive(
        const VirgilByteArray& in, const VirgilByteArray& salt, const VirgilByteArray& info, size_t outSize) const {

    if (outSize == 0) {
        throw make_error(VirgilCryptoError::InvalidArgument, "HKDF output size is zero. It should be positive.");
    }
    return expand(extract(in, salt), info, outSize);
}

VirgilByteArray VirgilHKDF::extract(const VirgilByteArray& keyMaterial, const VirgilByteArray& salt) const {
    auto hash = VirgilHash(hashAlgorithm_);
    hash.hmacStart(salt);
    hash.hmacUpdate(keyMaterial);
    return hash.hmacFinish();
}


VirgilByteArray VirgilHKDF::expand(
        const VirgilByteArray& pseudoRandomKey, const VirgilByteArray& info, size_t outSize) const {

    auto hash = VirgilHash(hashAlgorithm_);
    assert(hash.size() != 0 && "Hash algorithm size can not be zero.");
    if (outSize > 255 * hash.size()) {
        throw make_error(VirgilCryptoError::InvalidArgument,
                         "Requested output size for HKDF exceeds maximum (255 * HashLen).");
    }

    auto currentHash = VirgilByteArray();
    auto derivedData = VirgilByteArray();
    unsigned char counter = 0x00;
    hash.hmacStart(pseudoRandomKey);
    do {
        hash.hmacReset();
        hash.hmacUpdate(currentHash);
        hash.hmacUpdate(info);
        hash.hmacUpdate(VirgilByteArray(1, ++counter));
        currentHash = hash.hmacFinish();
        derivedData.insert(derivedData.end(), currentHash.cbegin(), currentHash.cend());
    } while (derivedData.size() < outSize);

    derivedData.resize(outSize); // trim

    return derivedData;
}
