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

#include <virgil/service/VirgilSigner.h>
using virgil::service::VirgilSigner;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/crypto/VirgilHash.h>
using virgil::crypto::VirgilHash;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

VirgilSigner::VirgilSigner(const VirgilHash& hash) : hash_(hash) {
}

VirgilSign VirgilSigner::sign(const VirgilByteArray& data, const VirgilByteArray& signerCertificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilByteArray digest = hash_.hash(data);

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    VirgilByteArray sign = cipher.sign(digest);

    return VirgilSign(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(hash_.name()), sign, signerCertificateId);
}

bool VirgilSigner::verify(const VirgilByteArray& data, const VirgilSign& sign, const VirgilByteArray& publicKey) {
    VirgilHash hash = VirgilHash::withName(sign.hashName());
    VirgilByteArray digest = hash.hash(data);

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPublicKey(publicKey);
    return cipher.verify(digest, sign.signedDigest());
}

VirgilSign VirgilSigner::sign(const VirgilAsn1Compatible& asn1Object, const VirgilByteArray& signerCertificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilByteArray digest = hash_.hash(asn1Object.toAsn1());

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    VirgilByteArray sign = cipher.sign(digest);

    return VirgilSign(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(hash_.name()), sign, signerCertificateId);
}

bool VirgilSigner::verify(const VirgilAsn1Compatible& asn1Object, const VirgilSign& sign,
            const VirgilByteArray& publicKey) {
    VirgilHash hash = VirgilHash::withName(sign.hashName());

    VirgilByteArray digest = hash.hash(asn1Object.toAsn1());

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPublicKey(publicKey);
    return cipher.verify(digest, sign.signedDigest());
}

