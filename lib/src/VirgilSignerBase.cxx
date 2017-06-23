/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#include <virgil/crypto/VirgilSignerBase.h>

#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::VirgilSignerBase;
using virgil::crypto::VirgilByteArray;

using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

VirgilSignerBase::VirgilSignerBase(VirgilHash::Algorithm hashAlgorithm)
        : hash_(hashAlgorithm), pk_() {
}

VirgilHash::Algorithm VirgilSignerBase::getHashAlgorithm() const {
    return hash_.algorithm();
}

VirgilByteArray VirgilSignerBase::signHash(
        const VirgilByteArray& digest, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {
    return doSignHash(digest, privateKey, privateKeyPassword);
}

bool VirgilSignerBase::verifyHash(
        const VirgilByteArray& digest, const VirgilByteArray& signature, const VirgilByteArray& publicKey) {
    return doVerifyHash(digest, signature, publicKey);
}

VirgilByteArray VirgilSignerBase::packSignature(const VirgilByteArray& signature) const {
    VirgilAsn1Writer asn1Writer;
    size_t asn1Len = 0;
    asn1Len += asn1Writer.writeOctetString(signature);
    asn1Len += VirgilHash(getHashAlgorithm()).asn1Write(asn1Writer);
    (void) asn1Writer.writeSequence(asn1Len);
    return asn1Writer.finish();
}

VirgilByteArray VirgilSignerBase::unpackSignature(const VirgilByteArray& packedSignature) {
    VirgilAsn1Reader asn1Reader(packedSignature);
    asn1Reader.readSequence();
    VirgilHash hash;
    hash.asn1Read(asn1Reader);
    auto signature = asn1Reader.readOctetString();
    hash_ = std::move(hash);
    return signature;
}

VirgilByteArray VirgilSignerBase::doSignHash(
        const VirgilByteArray& digest, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    pk_.setPrivateKey(privateKey, privateKeyPassword);
    return pk_.sign(digest, hash_.type());
}

bool VirgilSignerBase::doVerifyHash(
        const VirgilByteArray& digest, const VirgilByteArray& signature, const VirgilByteArray& publicKey) {

    pk_.setPublicKey(publicKey);
    return pk_.verify(digest, signature, hash_.type());
}
