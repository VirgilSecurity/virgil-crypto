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

#include <virgil/service/VirgilChunkCipher.h>
using virgil::service::VirgilChunkCipher;

#include <cstring>
#include <cmath>

#include <string>
using std::string;

#include <sstream>
using std::ostringstream;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <virgil/crypto/VirgilSymmetricCipher.h>
using virgil::crypto::VirgilSymmetricCipher;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

/**
 * @name Contsants
 */
///@{
static const char * const kCustomParameterKey_ChunkSize = "chunkSize";
///@}

VirgilChunkCipher::~VirgilChunkCipher() throw() {
}

static size_t adjustEncryptionChunkSize(size_t preferredChunkSize, size_t cipherBlockSize) {
    if (preferredChunkSize < cipherBlockSize) {
        return cipherBlockSize - 1;
    } else {
        return (size_t)(preferredChunkSize / cipherBlockSize) * cipherBlockSize - 1;
    }
}

static size_t adjustDecryptionChunkSize(size_t encryptionChunkSize, size_t cipherBlockSize) {
    return (size_t)ceil((double)encryptionChunkSize / cipherBlockSize) * cipherBlockSize;
}

size_t VirgilChunkCipher::startEncryption(size_t preferredChunkSize) {
    VirgilSymmetricCipher& symmetricCipher = initEncryption();
    size_t actualChunkSize = adjustEncryptionChunkSize(preferredChunkSize, symmetricCipher.blockSize());
    storeChunkSize(actualChunkSize);
    return actualChunkSize;
}

size_t VirgilChunkCipher::startDecryptionWithKey(const VirgilByteArray& certificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilSymmetricCipher& symmetricCipher = initDecryptionWithKey(certificateId, privateKey, privateKeyPassword);
    return adjustDecryptionChunkSize(retrieveChunkSize(), symmetricCipher.blockSize());
}

size_t VirgilChunkCipher::startDecryptionWithPassword(const VirgilByteArray& pwd) {
    VirgilSymmetricCipher& symmetricCipher = initDecryptionWithPassword(pwd);
    return adjustDecryptionChunkSize(retrieveChunkSize(), symmetricCipher.blockSize());
}

VirgilByteArray VirgilChunkCipher::process(const VirgilByteArray& data) {
    VirgilSymmetricCipher& symmetricCipher = getSymmetricCipher();
    bool isDataAlignedToBlockSize = (data.size() % symmetricCipher.blockSize()) == 0;
    if (symmetricCipher.isDecryptionMode() && !isDataAlignedToBlockSize) {
        ostringstream message;
        message << "In the decryption mode data size MUST be multiple of ";
        message << symmetricCipher.blockSize() << " bytes.";
        throw VirgilException(message.str());
    }

    symmetricCipher.reset();
    VirgilByteArray firstChunk = symmetricCipher.update(data);
    VirgilByteArray secondChunk = symmetricCipher.finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), secondChunk.begin(), secondChunk.end());

    return result;
}

void VirgilChunkCipher::finalize() {
    if (getSymmetricCipher().isEncryptionMode()) {
        buildContentInfo();
    }
    clearCipherInfo();
}

void VirgilChunkCipher::storeChunkSize(size_t chunkSize) {
    customParameters().setInteger(
            VIRGIL_BYTE_ARRAY_FROM_C_STRING(kCustomParameterKey_ChunkSize), chunkSize);
}

size_t VirgilChunkCipher::retrieveChunkSize() const {
    return customParameters().getInteger(
            VIRGIL_BYTE_ARRAY_FROM_C_STRING(kCustomParameterKey_ChunkSize));
}


