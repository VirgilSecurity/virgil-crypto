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

#include <virgil/crypto/VirgilStreamCipher.h>

#include <virgil/crypto/foundation/VirgilKDF.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

#include "ScopeGuard.h"

using virgil::crypto::VirgilStreamCipher;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilDataSource;
using virgil::crypto::VirgilDataSink;

using virgil::crypto::foundation::VirgilKDF;
using virgil::crypto::foundation::VirgilSymmetricCipher;
using virgil::crypto::foundation::VirgilAsymmetricCipher;

void VirgilStreamCipher::encrypt(VirgilDataSource& source, VirgilDataSink& sink, bool embedContentInfo) {

    auto disposer = ScopeGuard([this]() {
        clear();
    });

    initEncryption();

    buildContentInfo();

    if (embedContentInfo) {
        VirgilDataSink::safeWrite(sink, getContentInfo());
    }

    while (source.hasData() && sink.isGood()) {
        VirgilDataSink::safeWrite(sink, getSymmetricCipher().update(source.read()));
    }

    VirgilDataSink::safeWrite(sink, getSymmetricCipher().finish());
}


void VirgilStreamCipher::decryptWithKey(
        VirgilDataSource& source, VirgilDataSink& sink,
        const VirgilByteArray& recipientId, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    initDecryptionWithKey(recipientId, privateKey, privateKeyPassword);

    decrypt(source, sink);
}


void VirgilStreamCipher::decryptWithPassword(
        VirgilDataSource& source, VirgilDataSink& sink,
        const VirgilByteArray& pwd) {

    initDecryptionWithPassword(pwd);

    decrypt(source, sink);
}


void VirgilStreamCipher::decrypt(VirgilDataSource& source, VirgilDataSink& sink) {

    auto disposer = ScopeGuard([this]() {
        clear();
    });

    while (source.hasData() && sink.isGood()) {
        VirgilByteArray payload = filterAndSetupContentInfo(source.read(), false);

        if (isReadyForDecryption()) {
            VirgilDataSink::safeWrite(sink, getSymmetricCipher().update(payload));
        }
    }

    VirgilByteArray payload = filterAndSetupContentInfo(VirgilByteArray(), true);
    VirgilDataSink::safeWrite(sink, getSymmetricCipher().update(payload));
    VirgilDataSink::safeWrite(sink, getSymmetricCipher().finish());
}
