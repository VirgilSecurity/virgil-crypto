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

#include <virgil/service/stream/VirgilStreamSigner.h>
using virgil::service::stream::VirgilStreamSigner;

#include <virgil/service/stream/VirgilDataSource.h>
using virgil::service::stream::VirgilDataSource;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/crypto/VirgilHash.h>
using virgil::crypto::VirgilHash;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

VirgilStreamSigner::VirgilStreamSigner(const VirgilHash& hash) : hash_(hash) {
}

VirgilSign VirgilStreamSigner::sign(VirgilDataSource& source, const VirgilByteArray& signerCertificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    hash_.start();
    while (source.hasData()) {
        hash_.update(source.read());
    }
    VirgilByteArray digest = hash_.finish();

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    VirgilByteArray sign = cipher.sign(digest);

    return VirgilSign(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(hash_.name()), sign, signerCertificateId);
}

bool VirgilStreamSigner::verify(VirgilDataSource& source, const VirgilSign& sign, const VirgilByteArray& publicKey) {
    VirgilHash hash = VirgilHash::withName(sign.hashName());
    hash.start();
    while (source.hasData()) {
        hash.update(source.read());
    }
    VirgilByteArray digest = hash.finish();

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPublicKey(publicKey);
    return cipher.verify(digest, sign.signedDigest());
}

