/**
 * Copyright (C) 2015 Virgil Security Inc.
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

/**
 * @file test_chunk_cipher.cxx
 * @brief Covers class VirgilCipher
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilChunkCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::str2bytes;
using virgil::crypto::bytes2hex;
using virgil::crypto::bytes2str;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilChunkCipher;
using virgil::crypto::VirgilKeyPair;

TEST_CASE("Encrypt and decrypt with generated keys", "[chunk-cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray plainData = str2bytes("!this string will be encrypted with chunk cipher!");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair(password);

    VirgilChunkCipher cipher;
    cipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        size_t chunkSize = cipher.startEncryption(16);
        VirgilByteArray encryptedData;
        for (size_t pos = 0; pos < plainData.size(); pos += chunkSize) {
            size_t adjustedChunkSize = std::min(chunkSize, plainData.size() - pos);
            VirgilByteArray::const_iterator start = plainData.begin() + pos;
            VirgilByteArray::const_iterator end = start + adjustedChunkSize;
            VirgilByteArray encryptedChunk = cipher.process(VirgilByteArray(start, end));
            encryptedData.insert(encryptedData.end(), encryptedChunk.begin(), encryptedChunk.end());
        }
        cipher.finish();

        VirgilByteArray decryptedData;
        chunkSize = cipher.startDecryptionWithKey(recipientId, keyPair.privateKey(), password);
        for (size_t pos = 0; pos < encryptedData.size(); pos += chunkSize) {
            size_t adjustedChunkSize = std::min(chunkSize, encryptedData.size() - pos);
            VirgilByteArray::const_iterator start = encryptedData.begin() + pos;
            VirgilByteArray::const_iterator end = start + adjustedChunkSize;
            VirgilByteArray decryptedChunk = cipher.process(VirgilByteArray(start, end));
            decryptedData.insert(decryptedData.end(), decryptedChunk.begin(), decryptedChunk.end());
        }

        REQUIRE(bytes2str(plainData) == bytes2str(decryptedData));
    }
}
