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

#include <virgil/crypto/VirgilChunkCipher.h>

#include <cmath>
#include <limits>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilChunkCipher;
using virgil::crypto::VirgilDataSource;
using virgil::crypto::VirgilDataSink;
using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::VirgilSymmetricCipher;

/**
 * @name Contsants
 */
///@{
static const char* const kCustomParameterKey_ChunkSize = "chunkSize";
///@}

namespace virgil { namespace crypto { namespace internal {

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

static void increment_octets(VirgilByteArray& octets) {
    for (VirgilByteArray::reverse_iterator it = octets.rbegin(); it != octets.rend(); ++it) {
        if (++(*it) != 0) { break; }
    }
}

static VirgilByteArray xor_octets(const VirgilByteArray& src, const VirgilByteArray& noise) {
    size_t noiseByteReversePos = noise.size();
    VirgilByteArray result(src);
    for (VirgilByteArray::reverse_iterator it = result.rbegin();
         it != result.rend() && noiseByteReversePos != 0; ++it, --noiseByteReversePos) {
        *it ^= noise[noiseByteReversePos - 1];
    }
    return result;
}

static VirgilByteArray make_unique_nonce(const VirgilByteArray& nonce, const VirgilByteArray& counter) {
    return xor_octets(nonce, counter);
}

static void process(
        VirgilDataSource& source, VirgilDataSink& sink, VirgilSymmetricCipher& symmetricCipher,
        size_t actualChunkSize, const VirgilByteArray& firstChunk = {}) {
    VirgilByteArray nonceCounter(symmetricCipher.ivSize());
    const VirgilByteArray nonce = symmetricCipher.iv();

    VirgilByteArray data(firstChunk);
    do {
        // Collect data for full chunk
        while (source.hasData() && data.size() < actualChunkSize) {
            VirgilByteArrayUtils::append(data, source.read());
        }
        // Process (encrypt/decrypt)
        while (data.size() >= actualChunkSize || (!data.empty() && !source.hasData())) {
            // Reconfigure symmetric cipher
            symmetricCipher.setIV(internal::make_unique_nonce(nonce, nonceCounter));
            symmetricCipher.reset();
            const VirgilByteArray chunk = VirgilByteArrayUtils::popBytes(data, actualChunkSize);
            VirgilByteArray processedChunk;
            VirgilByteArrayUtils::append(processedChunk, symmetricCipher.update(chunk));
            VirgilByteArrayUtils::append(processedChunk, symmetricCipher.finish());
            internal::increment_octets(nonceCounter);
            VirgilDataSink::safeWrite(sink, processedChunk);
        }
    } while (source.hasData());
}

}}}

void VirgilChunkCipher::encrypt(
        VirgilDataSource& source, VirgilDataSink& sink, bool embedContentInfo, size_t preferredChunkSize) {
    VirgilSymmetricCipher& symmetricCipher = initEncryption();

    const size_t actualChunkSize = internal::adjustEncryptionChunkSize(preferredChunkSize, symmetricCipher.blockSize(),
            symmetricCipher.isSupportPadding());
    storeChunkSize(actualChunkSize);
    buildContentInfo();

    if (embedContentInfo) {
        VirgilDataSink::safeWrite(sink, getContentInfo());
    }

    internal::process(source, sink, symmetricCipher, actualChunkSize);

    clearCipherInfo();
}

void VirgilChunkCipher::decryptWithKey(
        VirgilDataSource& source, VirgilDataSink& sink, const VirgilByteArray& recipientId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {

    const VirgilByteArray firstChunk = tryReadContentInfo(source);

    VirgilSymmetricCipher& symmetricCipher = initDecryptionWithKey(recipientId, privateKey, privateKeyPassword);

    const size_t actualChunkSize = internal::adjustDecryptionChunkSize(retrieveChunkSize(),
            symmetricCipher.blockSize(), symmetricCipher.isSupportPadding(), symmetricCipher.authTagLength());

    internal::process(source, sink, symmetricCipher, actualChunkSize, firstChunk);

    clearCipherInfo();
}

void VirgilChunkCipher::decryptWithPassword(
        VirgilDataSource& source, VirgilDataSink& sink, const VirgilByteArray& pwd) {

    const VirgilByteArray firstChunk = tryReadContentInfo(source);

    VirgilSymmetricCipher& symmetricCipher = initDecryptionWithPassword(pwd);

    const size_t actualChunkSize = internal::adjustDecryptionChunkSize(retrieveChunkSize(),
            symmetricCipher.blockSize(), symmetricCipher.isSupportPadding(), symmetricCipher.authTagLength());

    internal::process(source, sink, symmetricCipher, actualChunkSize, firstChunk);

    clearCipherInfo();
}

void VirgilChunkCipher::storeChunkSize(size_t chunkSize) {
    if (chunkSize > std::numeric_limits<int>::max()) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Chunk size is too big.");
    }
    customParams().setInteger(str2bytes(kCustomParameterKey_ChunkSize), static_cast<int>(chunkSize));
}

size_t VirgilChunkCipher::retrieveChunkSize() const {
    const int chunkSize = customParams().getInteger(str2bytes(kCustomParameterKey_ChunkSize));
    if (chunkSize < 0) {
        throw make_error(VirgilCryptoError::InvalidFormat, "Retrieved chunk size is negative.");
    }
    return static_cast<size_t>(chunkSize);
}

VirgilByteArray VirgilChunkCipher::tryReadContentInfo(VirgilDataSource& source) {
    const size_t minDataSize = 16;
    VirgilByteArray data;
    while (data.size() < minDataSize && source.hasData()) {
        VirgilByteArray nextData = source.read();
        data.insert(data.end(), nextData.begin(), nextData.end());
    }
    size_t contentInfoSize = defineContentInfoSize(data);
    if (contentInfoSize > 0) {
        while (data.size() < contentInfoSize && source.hasData()) {
            VirgilByteArray nextData = source.read();
            data.insert(data.end(), nextData.begin(), nextData.end());
        }
        return VirgilCipherBase::tryReadContentInfo(data);
    }
    return data;
}
