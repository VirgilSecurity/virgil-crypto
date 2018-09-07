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

#include <virgil/crypto/VirgilSeqCipher.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>

#include "ScopeGuard.h"

using virgil::crypto::VirgilSeqCipher;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::foundation::VirgilSymmetricCipher;

using virgil::crypto::make_error;

VirgilByteArray VirgilSeqCipher::startEncryption() {

    initEncryption();

    buildContentInfo();

    return getContentInfo();
}


void VirgilSeqCipher::startDecryptionWithKey(
        const VirgilByteArray& recipientId, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    initDecryptionWithKey(recipientId, privateKey, privateKeyPassword);
}


void VirgilSeqCipher::startDecryptionWithPassword(const VirgilByteArray& pwd) {
    initDecryptionWithPassword(pwd);
}


VirgilByteArray VirgilSeqCipher::process(const VirgilByteArray& data) {

    if (!isInited()) {
        throw make_error(VirgilCryptoError::InvalidState,
            "VirgilSeqCipher::process() can not be called before any 'start' function is called.");
    }

    auto disposer = ScopeGuardOnException([this]() {
        clear();
    });

    if (isReadyForEncryption()) {
        return getSymmetricCipher().update(data);

    } else {
        VirgilByteArray payload = filterAndSetupContentInfo(data, false);

        if (isReadyForDecryption()) {
            return getSymmetricCipher().update(payload);
        }
    }

    return VirgilByteArray();
}


VirgilByteArray VirgilSeqCipher::finish() {

    auto disposer = ScopeGuard([this]() {
        clear();
    });

    if (isReadyForEncryption()) {
        return getSymmetricCipher().finish();

    } else {
        VirgilByteArray payload = filterAndSetupContentInfo(VirgilByteArray(), true);

        if (isReadyForDecryption()) {
            VirgilByteArray plainText = getSymmetricCipher().update(payload);
            VirgilByteArrayUtils::append(plainText, getSymmetricCipher().finish());
            return plainText;
        }
    }

    throw make_error(VirgilCryptoError::InvalidState, "VirgilSeqCipher::finish()");
}
