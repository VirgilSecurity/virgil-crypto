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

VirgilChunkCipher::VirgilChunkCipher() : symmetricCipher_(VirgilSymmetricCipher::aes256()) {
}

VirgilChunkCipher::~VirgilChunkCipher() throw() {
}

size_t VirgilChunkCipher::adjustEncryptionChunkSize(size_t preferredChunkSize) const {
    size_t blockSize = symmetricCipher_.blockSize();
    if (preferredChunkSize < blockSize) {
        return blockSize - 1;
    } else {
        return (size_t)(preferredChunkSize / blockSize) * blockSize - 1;
    }
}

size_t VirgilChunkCipher::adjustDecryptionChunkSize(size_t encryptionChunkSize) const {
    size_t blockSize = symmetricCipher_.blockSize();
    return (size_t)ceil((double)encryptionChunkSize / blockSize) * blockSize;
}

VirgilByteArray VirgilChunkCipher::startEncryption(const VirgilByteArray& publicKey) {
    VirgilByteArray encryptionKey = configureEncryption(symmetricCipher_);
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPublicKey(publicKey);
    return asymmetricCipher.encrypt(encryptionKey);
}

void VirgilChunkCipher::startDecryption(const VirgilByteArray& encryptionKey, const VirgilByteArray& privateKey,
                const VirgilByteArray& privateKeyPassword) {
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPrivateKey(privateKey, privateKeyPassword);

    configureDecryption(symmetricCipher_, asymmetricCipher.decrypt(encryptionKey));
}

VirgilByteArray VirgilChunkCipher::process(const VirgilByteArray& data) {
    bool dataIsAlignedToBlockSize = (data.size() % symmetricCipher_.blockSize()) == 0;
    if (symmetricCipher_.isDecryptionMode() && !dataIsAlignedToBlockSize) {
        ostringstream message;
        message << "In the decryption mode data size MUST be multiple of ";
        message << symmetricCipher_.blockSize() << " bytes.";
        throw VirgilException(message.str());
    }

    symmetricCipher_.reset();
    VirgilByteArray firstChunk = symmetricCipher_.update(data);
    VirgilByteArray secondChunk = symmetricCipher_.finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), secondChunk.begin(), secondChunk.end());

    return result;
}

void VirgilChunkCipher::finalize() {
    symmetricCipher_.clear();
}
