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

/**
 * @file test_chunk_cipher.cxx
 * @brief Covers class VirgilChunkCipher
 */

#if VIRGIL_CRYPTO_FEATURE_STREAM_IMPL

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilChunkCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/stream/VirgilBytesDataSource.h>
#include <virgil/crypto/stream/VirgilBytesDataSink.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

using virgil::crypto::str2bytes;
using virgil::crypto::bytes2hex;
using virgil::crypto::bytes2str;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilChunkCipher;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::stream::VirgilBytesDataSource;
using virgil::crypto::stream::VirgilBytesDataSink;
using virgil::crypto::foundation::VirgilBase64;

TEST_CASE("VirgilChunkCipher: encrypt and decrypt with generated keys", "[chunk-cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair = VirgilKeyPair::generateRecommended(password);

    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilBytesDataSource testDataSource(testData);

    VirgilByteArray encryptedData;
    VirgilBytesDataSink encryptedDataSink(encryptedData);
    VirgilBytesDataSource encryptedDataSource(encryptedData);

    VirgilByteArray decryptedData;
    VirgilBytesDataSink decryptedDataSink(decryptedData);

    VirgilChunkCipher encCipher;
    VirgilChunkCipher decCipher;
    encCipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        testDataSource.reset();
        encryptedDataSource.reset();
        decryptedDataSink.reset();

        encCipher.encrypt(testDataSource, encryptedDataSink, true, 3);

        encryptedDataSource.reset();
        decryptedDataSink.reset();
        REQUIRE_THROWS(
                decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, recipientId, keyPair.privateKey())
        );
        encryptedDataSource.reset();
        decryptedDataSink.reset();
        REQUIRE_NOTHROW(
                decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, recipientId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);
    }

    SECTION("and embedded content info with custom parameters") {
        VirgilByteArray intParamKey = str2bytes("int_parameter_key");
        const int intParamValue = 35777;
        VirgilByteArray strParamKey = str2bytes("string_parameter_key");
        VirgilByteArray strParamValue = str2bytes("string parameter");
        VirgilByteArray hexParamKey = str2bytes("data_param_value");
        VirgilByteArray hexParamValue = str2bytes("will be stored as octet string");

        encCipher.customParams().setInteger(intParamKey, intParamValue);
        encCipher.customParams().setString(strParamKey, strParamValue);
        encCipher.customParams().setData(hexParamKey, hexParamValue);

        testDataSource.reset();
        encryptedDataSource.reset();
        decryptedDataSink.reset();

        encCipher.encrypt(testDataSource, encryptedDataSink, true);
        encCipher.removeAllRecipients();
        encCipher.customParams().clear();

        encryptedDataSource.reset();
        decryptedDataSink.reset();
        REQUIRE_NOTHROW(
                decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, recipientId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(decCipher.customParams().getInteger(intParamKey) == intParamValue);
        REQUIRE(decCipher.customParams().getString(strParamKey) == strParamValue);
        REQUIRE(decCipher.customParams().getData(hexParamKey) == hexParamValue);
    }

    SECTION("and separated content info") {
        testDataSource.reset();
        encryptedDataSource.reset();
        decryptedDataSink.reset();

        encCipher.encrypt(testDataSource, encryptedDataSink, false);
        VirgilByteArray contentInfo = encCipher.getContentInfo();
        REQUIRE(contentInfo.size() > 0);
        encCipher.removeAllRecipients();
        encCipher.customParams().clear();

        REQUIRE_NOTHROW(
                decCipher.setContentInfo(contentInfo)
        );
        encryptedDataSource.reset();
        decryptedDataSink.reset();
        REQUIRE_THROWS(
                decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, recipientId, keyPair.privateKey())
        );
        encryptedDataSource.reset();
        decryptedDataSink.reset();
        REQUIRE_NOTHROW(
                decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, recipientId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);
    }

    SECTION("and separated content info with custom parameters") {
        VirgilByteArray intParamKey = str2bytes("int_parameter_key");
        const int intParamValue = 35777;
        VirgilByteArray strParamKey = str2bytes("string_parameter_key");
        VirgilByteArray strParamValue = str2bytes("string parameter");
        VirgilByteArray hexParamKey = str2bytes("data_param_value");
        VirgilByteArray hexParamValue = str2bytes("will be stored as octet string");

        encCipher.customParams().setInteger(intParamKey, intParamValue);
        encCipher.customParams().setString(strParamKey, strParamValue);
        encCipher.customParams().setData(hexParamKey, hexParamValue);

        testDataSource.reset();
        encryptedDataSource.reset();
        decryptedDataSink.reset();

        encCipher.encrypt(testDataSource, encryptedDataSink, false);
        VirgilByteArray contentInfo = encCipher.getContentInfo();
        encCipher.removeAllRecipients();
        encCipher.customParams().clear();

        REQUIRE_NOTHROW(
                decCipher.setContentInfo(contentInfo)
        );

        encryptedDataSource.reset();
        decryptedDataSink.reset();
        REQUIRE_NOTHROW(
                decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, recipientId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(decCipher.customParams().getInteger(intParamKey) == intParamValue);
        REQUIRE(decCipher.customParams().getString(strParamKey) == strParamValue);
        REQUIRE(decCipher.customParams().getData(hexParamKey) == hexParamValue);
    }
}

TEST_CASE("VirgilChunkCipher: generated keys", "[chunk-cipher]") {
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray bobId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilByteArray johnId = str2bytes("968dc52d-2045-4abe-ab51-0b04737cac76");
    VirgilKeyPair bobKeyPair = VirgilKeyPair::generateRecommended();
    VirgilKeyPair johnKeyPair = VirgilKeyPair::generateRecommended();
    VirgilByteArray alicePassword = str2bytes("alice secret");

    VirgilBytesDataSource testDataSource(testData);

    VirgilByteArray encryptedData;
    VirgilBytesDataSink encryptedDataSink(encryptedData);
    VirgilBytesDataSource encryptedDataSource(encryptedData);

    VirgilByteArray decryptedData;
    VirgilBytesDataSink decryptedDataSink(decryptedData);

    VirgilChunkCipher encCipher;
    VirgilChunkCipher decCipher;
    encCipher.addKeyRecipient(bobId, bobKeyPair.publicKey());
    encCipher.addKeyRecipient(johnId, johnKeyPair.publicKey());
    encCipher.addPasswordRecipient(alicePassword);

    SECTION("encrypt for multiple recipients with embedded content info") {
        encCipher.encrypt(testDataSource, encryptedDataSink, true);
        encCipher.removeAllRecipients();

        SECTION("decrypt for Bob") {
            encryptedDataSource.reset();
            decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, bobId, bobKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for John") {
            encryptedDataSource.reset();
            decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, johnId, johnKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for Alice") {
            encryptedDataSource.reset();
            decCipher.decryptWithPassword(encryptedDataSource, decryptedDataSink, alicePassword);
            REQUIRE(testData == decryptedData);
        }
    }

    SECTION("encrypt for multiple recipients with separated content info") {
        encCipher.encrypt(testDataSource, encryptedDataSink, false);
        VirgilByteArray contentInfo = encCipher.getContentInfo();
        encCipher.removeAllRecipients();

        REQUIRE_NOTHROW(
                decCipher.setContentInfo(contentInfo)
        );

        SECTION("decrypt for Bob") {
            encryptedDataSource.reset();
            decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, bobId, bobKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for John") {
            encryptedDataSource.reset();
            decCipher.decryptWithKey(encryptedDataSource, decryptedDataSink, johnId, johnKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for Alice") {
            encryptedDataSource.reset();
            decCipher.decryptWithPassword(encryptedDataSource, decryptedDataSink, alicePassword);
            REQUIRE(testData == decryptedData);
        }
    }
}

TEST_CASE("VirgilChunkCipher: data read from a source by one pass", "[chunk-cipher]") {
    VirgilByteArray encryptedData = VirgilBase64::decode(
            "MIIBegIBADCCAVsGCSqGSIb3DQEHA6CCAUwwggFIAgECMYIBGTCCARUCAQKgIgQg3OSMIJkPbdDdMCZ8"
                    "62YN1WZgdwQFX1dt7c2ZCMM9su4wBwYDK2VwBQAEgeIwgd8CAQAwKjAFBgMrZXADIQAILc51E+qsD5zb"
                    "H56fzjYvaSsGndig3WrMvdlpjAF7YzAYBgcogYxxAgUCMA0GCWCGSAFlAwQCAgUAMEEwDQYJYIZIAWUD"
                    "BAICBQAEMEW1RpGN0v6BUfTCERATacq+SjktHcD4CuNXCkXKeCD5wzco4firwgNJnj3yO/A9lTBRMB0G"
                    "CWCGSAFlAwQBKgQQDzZ6ZT9Zlp+tZwPL5KpCiwQw6DkOg8QCf1mTzVst7GNj9i39C6cudIx5rozoOPLD"
                    "5zKvA94YLM6f3tdnhyvh10auMCYGCSqGSIb3DQEHATAZBglghkgBZQMEAS4EDMYL9mftkelU8Vg4s6AW"
                    "MRQwEgwJY2h1bmtTaXploAUCAxAAADn8INszCuazHwo8OBEQzNDp6HQAVXsmpsVrnMqapQs+XPxV7pW1"
                    "QNc+vYCDsMY5V2HUApE=");
    VirgilByteArray publicKey = VirgilBase64::decode(
            "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQTBmN1J1K2k1REdpSFRRVFlX"
                    "d3dUTllBbVVQK2x3U2VhbXdoS29wUFNBV009Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=");
    VirgilByteArray privateKey = VirgilBase64::decode(
            "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUwrR2tCTjJnelNH"
                    "Mkp0azdsQWtDRit5SDBxZUoxMDRPR1JHcTNDQjVBSWMKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=");
    VirgilByteArray recipientId = VirgilBase64::decode("3OSMIJkPbdDdMCZ862YN1WZgdwQFX1dt7c2ZCMM9su4=");

    VirgilByteArray decryptedData;
    VirgilBytesDataSource encryptedSource(encryptedData, encryptedData.size());
    VirgilBytesDataSink decryptedSink(decryptedData);

    VirgilChunkCipher cipher;

    REQUIRE(VirgilKeyPair::isKeyPairMatch(publicKey, privateKey));
    REQUIRE_NOTHROW(cipher.decryptWithKey(encryptedSource, decryptedSink, recipientId, privateKey));
    REQUIRE(decryptedData.size() > 0);
    REQUIRE(bytes2str(decryptedData) == "538DF736-57A0-4B39-B695-73681E59EAAC");
}

#else
#if defined(_MSC_VER)
#pragma message("Tests for class VirgilChunkCipher are ignored, because VIRGIL_CRYPTO_FEATURE_STREAM_IMPL build parameter is not defined")
#else
#warning "Tests for class VirgilChunkCipher are ignored, because VIRGIL_CRYPTO_FEATURE_STREAM_IMPL build parameter is not defined"
#endif /* _MSC_VER */
#endif /* VIRGIL_CRYPTO_FEATURE_STREAM_IMPL */
