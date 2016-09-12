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

#ifndef VIRGIL_CRYPTO_CONFIG_FILE
#include <virgil/crypto/config.h>
#else
#include VIRGIL_CRYPTO_CONFIG_FILE
#endif

#if defined(VIRGIL_CRYPTO_CIPHER_MODULE)

#include <virgil/crypto/VirgilCipher.h>

#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>

using virgil::crypto::VirgilCipher;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilSymmetricCipher;

VirgilByteArray VirgilCipher::encrypt(const VirgilByteArray& data, bool embedContentInfo) {
    VirgilSymmetricCipher& symmetricCipher = initEncryption();
    VirgilByteArray encryptedData;

    buildContentInfo();
    if (embedContentInfo) {
        VirgilByteArray contentInfo = getContentInfo();
        encryptedData.swap(contentInfo);
    }

    VirgilByteArray firstChunk = symmetricCipher.update(data);
    VirgilByteArray secondChunk = symmetricCipher.finish();

    encryptedData.insert(encryptedData.end(), firstChunk.begin(), firstChunk.end());
    encryptedData.insert(encryptedData.end(), secondChunk.begin(), secondChunk.end());

    clearCipherInfo();
    return encryptedData;
}

VirgilByteArray VirgilCipher::decryptWithKey(
        const VirgilByteArray& encryptedData,
        const VirgilByteArray& recipientId, const VirgilByteArray& privateKey,
        const VirgilByteArray& privateKeyPassword) {

    VirgilByteArray payload = tryReadContentInfo(encryptedData);
    VirgilSymmetricCipher& cipher = initDecryptionWithKey(recipientId, privateKey, privateKeyPassword);
    return decrypt(payload, cipher);
}

VirgilByteArray VirgilCipher::decryptWithPassword(const VirgilByteArray& encryptedData, const VirgilByteArray& pwd) {
    VirgilByteArray payload = tryReadContentInfo(encryptedData);
    VirgilSymmetricCipher& cipher = initDecryptionWithPassword(pwd);
    return decrypt(payload, cipher);
}


VirgilByteArray VirgilCipher::decrypt(const VirgilByteArray& encryptedData, VirgilSymmetricCipher& cipher) {
    VirgilByteArray firstChunk = cipher.update(encryptedData);
    VirgilByteArray secondChunk = cipher.finish();

    VirgilByteArray decryptedData;
    decryptedData.insert(decryptedData.end(), firstChunk.begin(), firstChunk.end());
    decryptedData.insert(decryptedData.end(), secondChunk.begin(), secondChunk.end());

    clearCipherInfo();
    return decryptedData;
}

#endif //VIRGIL_CRYPTO_CIPHER_MODULE
