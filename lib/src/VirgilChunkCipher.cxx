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

#include <virgil/crypto/VirgilChunkCipher.h>

#include <cmath>
#include <limits>

#include <tinyformat/tinyformat.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilChunkCipher;
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::VirgilSymmetricCipher;

/**
 * @name Contsants
 */
///@{
static const char* const kCustomParameterKey_ChunkSize = "chunkSize";
///@}

static size_t adjustEncryptionChunkSize(size_t preferredChunkSize, size_t cipherBlockSize, bool isSupportPadding) {
    if (isSupportPadding) {
        if (preferredChunkSize < cipherBlockSize) {
            return cipherBlockSize - 1;
        } else {
            return (size_t) (preferredChunkSize / cipherBlockSize) * cipherBlockSize - 1;
        }
    } else {
        return preferredChunkSize;
    }
}

static size_t adjustDecryptionChunkSize(
        size_t encryptionChunkSize, size_t cipherBlockSize, bool isSupportPadding,
        size_t authTagLength) {
    if (isSupportPadding) {
        return (size_t) ceil((double) encryptionChunkSize / cipherBlockSize) * cipherBlockSize + authTagLength;
    } else {
        return encryptionChunkSize + authTagLength;
    }
}

size_t VirgilChunkCipher::startEncryption(size_t preferredChunkSize) {
    VirgilSymmetricCipher& symmetricCipher = initEncryption();
    size_t actualChunkSize = adjustEncryptionChunkSize(preferredChunkSize,
            symmetricCipher.blockSize(), symmetricCipher.isSupportPadding());
    storeChunkSize(actualChunkSize);
    buildContentInfo();
    return actualChunkSize;
}

size_t VirgilChunkCipher::startDecryptionWithKey(
        const VirgilByteArray& recipientId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilSymmetricCipher& symmetricCipher = initDecryptionWithKey(recipientId, privateKey, privateKeyPassword);
    return adjustDecryptionChunkSize(retrieveChunkSize(),
            symmetricCipher.blockSize(), symmetricCipher.isSupportPadding(), symmetricCipher.authTagLength());
}

size_t VirgilChunkCipher::startDecryptionWithPassword(const VirgilByteArray& pwd) {
    VirgilSymmetricCipher& symmetricCipher = initDecryptionWithPassword(pwd);
    return adjustDecryptionChunkSize(retrieveChunkSize(),
            symmetricCipher.blockSize(), symmetricCipher.isSupportPadding(), symmetricCipher.authTagLength());
}

VirgilByteArray VirgilChunkCipher::process(const VirgilByteArray& data) {
    VirgilSymmetricCipher& symmetricCipher = getSymmetricCipher();
    if (symmetricCipher.isDecryptionMode() && symmetricCipher.isSupportPadding()) {
        bool isDataAlignedToBlockSize = (data.size() % symmetricCipher.blockSize()) == 0;
        if (!isDataAlignedToBlockSize) {
            throw make_error(VirgilCryptoError::InvalidArgument,
                    tfm::format("Expected block size: multiple of %s bytes.", symmetricCipher.blockSize()));
        }
    }

    symmetricCipher.reset();
    VirgilByteArray firstChunk = symmetricCipher.update(data);
    VirgilByteArray secondChunk = symmetricCipher.finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), secondChunk.begin(), secondChunk.end());

    return result;
}

void VirgilChunkCipher::finish() {
    clearCipherInfo();
}

void VirgilChunkCipher::storeChunkSize(size_t chunkSize) {
    if (chunkSize > std::numeric_limits<int>::max()) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Chunk size is too big.");
    }
    customParams().setInteger(str2bytes(kCustomParameterKey_ChunkSize), chunkSize);
}

size_t VirgilChunkCipher::retrieveChunkSize() const {
    return customParams().getInteger(str2bytes(kCustomParameterKey_ChunkSize));
}


