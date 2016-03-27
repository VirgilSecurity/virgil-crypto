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
 * @file test_stream_cipher.cxx
 * @brief Covers class VirgilStreamCipher
 */

#if defined(LIB_FILE_IO)

#include "catch.hpp"

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/stream/VirgilBytesDataSource.h>
#include <virgil/crypto/stream/VirgilBytesDataSink.h>

using virgil::crypto::str2bytes;
using virgil::crypto::bytes2hex;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilStreamCipher;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::stream::VirgilBytesDataSource;
using virgil::crypto::stream::VirgilBytesDataSink;

TEST_CASE("Stream Cipher: encrypt and decrypt with generated keys", "[stream-cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair(password);

    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilBytesDataSource testDataSource(testData);

    VirgilByteArray encryptedData;
    VirgilBytesDataSink encryptedDataSink(encryptedData);
    VirgilBytesDataSource encryptedDataSource(encryptedData);

    VirgilByteArray decryptedData;
    VirgilBytesDataSink decryptedDataSink(decryptedData);

    VirgilStreamCipher encCipher;
    VirgilStreamCipher decCipher;
    encCipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        testDataSource.reset();
        encryptedDataSource.reset();
        decryptedDataSink.reset();

        encCipher.encrypt(testDataSource, encryptedDataSink, true);

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

TEST_CASE("Stream Cipher: generated keys", "[stream-cipher]") {
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray bobId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilByteArray johnId = str2bytes("968dc52d-2045-4abe-ab51-0b04737cac76");
    VirgilKeyPair bobKeyPair;
    VirgilKeyPair johnKeyPair;
    VirgilByteArray alicePassword = str2bytes("alice secret");

    VirgilBytesDataSource testDataSource(testData);

    VirgilByteArray encryptedData;
    VirgilBytesDataSink encryptedDataSink(encryptedData);
    VirgilBytesDataSource encryptedDataSource(encryptedData);

    VirgilByteArray decryptedData;
    VirgilBytesDataSink decryptedDataSink(decryptedData);

    VirgilStreamCipher encCipher;
    VirgilStreamCipher decCipher;
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

#else
#if defined(_MSC_VER)
#pragma message("Tests for class VirgilStreamCipher are ignored, because LIB_FILE_IO build parameter is not defined")
#else
#warning "Tests for class VirgilStreamCipher are ignored, because LIB_FILE_IO build parameter is not defined"
#endif /* _MSC_VER */
#endif /* LIB_FILE_IO */
