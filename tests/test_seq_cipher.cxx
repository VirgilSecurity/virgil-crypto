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

/**
 * @file test_seq_cipher.cxx
 * @brief Covers class VirgilSeqCipher
 */


#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilSeqCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/stream/VirgilBytesDataSource.h>
#include <virgil/crypto/stream/VirgilBytesDataSink.h>

using virgil::crypto::str2bytes;
using virgil::crypto::bytes2hex;
using virgil::crypto::bytes_append;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilSeqCipher;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::stream::VirgilBytesDataSource;
using virgil::crypto::stream::VirgilBytesDataSink;

TEST_CASE("VirgilSeqCipher: encrypt and decrypt with generated keys", "[seq-cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair = VirgilKeyPair::generateRecommended(password);

    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray encryptedData;
    VirgilByteArray decryptedData;

    VirgilSeqCipher encCipher;
    VirgilSeqCipher decCipher;
    encCipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        encryptedData = encCipher.startEncryption();

        REQUIRE_NOTHROW(
            bytes_append(encryptedData, encCipher.process(testData));
            bytes_append(encryptedData, encCipher.finish());
        );

        REQUIRE_THROWS(
            decCipher.startDecryptionWithKey(recipientId, keyPair.privateKey());
            decryptedData = decCipher.process(encryptedData);
            bytes_append(decryptedData, decCipher.finish());
        );

        REQUIRE_NOTHROW(
            decCipher.startDecryptionWithKey(recipientId, keyPair.privateKey(), password);
            decryptedData = decCipher.process(encryptedData);
            bytes_append(decryptedData, decCipher.finish());
        );

        REQUIRE(testData == decryptedData);
    }

    SECTION("and separated content info") {
        VirgilByteArray contentInfo = encCipher.startEncryption();

        REQUIRE_NOTHROW(
            bytes_append(encryptedData, encCipher.process(testData));
            bytes_append(encryptedData, encCipher.finish());
        );

        decCipher.setContentInfo(contentInfo);

        REQUIRE_THROWS(
            decCipher.startDecryptionWithKey(recipientId, keyPair.privateKey());
            decryptedData = decCipher.process(encryptedData);
            bytes_append(decryptedData, decCipher.finish());
        );

        REQUIRE_NOTHROW(
            decCipher.startDecryptionWithKey(recipientId, keyPair.privateKey(), password);
            decryptedData = decCipher.process(encryptedData);
            bytes_append(decryptedData, decCipher.finish());
        );

        REQUIRE(testData == decryptedData);
    }
}
