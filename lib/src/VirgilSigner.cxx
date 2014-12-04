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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#include <cstring>

#include <string>
using std::string;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/stream/VirgilDataSource.h>
using virgil::service::stream::VirgilDataSource;

#include <virgil/service/stream/VirgilDataSink.h>
using virgil::service::stream::VirgilDataSink;

#include <virgil/service/data/marshalling/VirgilAsn1DataMarshaller.h>
using virgil::service::data::marshalling::VirgilAsn1DataMarshaller;

#include <virgil/crypto/VirgilHash.h>
using virgil::crypto::VirgilHash;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

VirgilSigner::VirgilSigner() {
}

VirgilSigner::~VirgilSigner() throw() {
}

VirgilSign VirgilSigner::sign(VirgilDataSource& source, const VirgilByteArray& signerCertificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilHash hash = VirgilHash::sha256();
    hash.start();
    while (source.hasData()) {
        hash.update(source.read());
    }
    VirgilByteArray digest = hash.finish();

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    VirgilByteArray sign = cipher.sign(digest);

    return VirgilSign(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(hash.name()), sign, signerCertificateId);
}

bool VirgilSigner::verify(VirgilDataSource& source, const VirgilSign& sign, const VirgilByteArray& publicKey) {
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

VirgilSign VirgilSigner::sign(VirgilTicket& ticket, const VirgilByteArray& signerCertificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilHash hash = VirgilHash::sha256();

    VirgilAsn1DataMarshaller marshaller;
    VirgilByteArray digest = hash.hash(marshaller.marshal(ticket));

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    VirgilByteArray sign = cipher.sign(digest);

    return VirgilSign(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(hash.name()), sign, signerCertificateId);
}

bool VirgilSigner::verify(VirgilTicket& ticket, const VirgilSign& sign, const VirgilByteArray& publicKey) {
    VirgilHash hash = VirgilHash::withName(sign.hashName());

    VirgilAsn1DataMarshaller marshaller;
    VirgilByteArray digest = hash.hash(marshaller.marshal(ticket));

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPublicKey(publicKey);
    return cipher.verify(digest, sign.signedDigest());
}

