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

#include <virgil/crypto/VirgilSeqSigner.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilSeqSigner;

using virgil::crypto::foundation::VirgilHash;


VirgilSeqSigner::VirgilSeqSigner (VirgilHash::Algorithm hashAlgorithm)
        : VirgilSignerBase (hashAlgorithm), unpackedSignature_(), hash_(hashAlgorithm) {}


void VirgilSeqSigner::startSigning() {
    hash_.start();
}


void VirgilSeqSigner::startVerifying(const VirgilByteArray& signature) {
    unpackedSignature_ = unpackSignature(signature);

    if (getHashAlgorithm() != hash_.algorithm()) {
        hash_ = VirgilHash(getHashAlgorithm());
    }

    hash_.start();
}


void VirgilSeqSigner::update(const VirgilByteArray& data) {
    hash_.update(data);
}


VirgilByteArray VirgilSeqSigner::sign(const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    // Get digest
    const auto digest = hash_.finish();

    // Sign digest
    const auto signature = signHash(digest, privateKey, privateKeyPassword);

    // Pack signature
    return packSignature(signature);
}


bool VirgilSeqSigner::verify(const VirgilByteArray& publicKey) {
    // Get digest
    const auto digest = hash_.finish();

    // Verify signature
    return verifyHash(digest, unpackedSignature_, publicKey);
}
