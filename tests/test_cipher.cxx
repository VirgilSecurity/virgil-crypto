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

/**
 * @file test_cipher.cxx
 * @brief Covers class VirgilCipher
 */

#include "catch.hpp"

#include <string>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/VirgilCipher.h>
using virgil::service::VirgilCipher;


TEST_CASE("encrypt and decrypt with generated keys", "[cipher]") {
    VirgilByteArray password = virgil_byte_array_from_c_string("password");
    VirgilByteArray testData = virgil_byte_array_from_c_string("this string will be encrypted");
    VirgilByteArray certificateId = virgil_byte_array_from_c_string("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair(password);

    VirgilCipher cipher;
    cipher.addKeyRecipient(certificateId, keyPair.publicKey());

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
            decryptedData = cipher.decryptWithKey(encryptedData, certificateId, keyPair.privateKey())
        );
        REQUIRE_NOTHROW(
            decryptedData = cipher.decryptWithKey(encryptedData, certificateId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);
    }

    SECTION("and embedded content info with custom parameters") {
        VirgilByteArray intParamKey = virgil_byte_array_from_c_string("int_parameter_key");
        const int intParamValue = 35777;
        VirgilByteArray strParamKey = virgil_byte_array_from_c_string("string_parameter_key");
        VirgilByteArray strParamValue = virgil_byte_array_from_c_string("string parameter");
        VirgilByteArray hexParamKey = virgil_byte_array_from_c_string("data_param_value");
        VirgilByteArray hexParamValue = virgil_byte_array_from_c_string("will be stored as octet string");

        cipher.customParameters().setInteger(intParamKey, intParamValue);
        cipher.customParameters().setString(strParamKey, strParamValue);
        cipher.customParameters().setData(hexParamKey, hexParamValue);

        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        cipher.removeAllRecipients();
        cipher.customParameters().clear();

        VirgilByteArray decryptedData;
        REQUIRE_NOTHROW(
            decryptedData = cipher.decryptWithKey(encryptedData, certificateId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(cipher.customParameters().getInteger(intParamKey) == intParamValue);
        REQUIRE(cipher.customParameters().getString(strParamKey) == strParamValue);
        REQUIRE(cipher.customParameters().getData(hexParamKey) == hexParamValue);
    }

    SECTION("and separated content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, false);
        VirgilByteArray contentInfo = cipher.getContentInfo();
        REQUIRE(contentInfo.size() > 0);

        REQUIRE_NOTHROW(
            cipher.setContentInfo(contentInfo)
        );

        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
            decryptedData = cipher.decryptWithKey(encryptedData, certificateId, keyPair.privateKey())
        );
        REQUIRE_NOTHROW(
            decryptedData = cipher.decryptWithKey(encryptedData, certificateId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);
    }

    SECTION("and separated content info with custom parameters") {
        VirgilByteArray intParamKey = virgil_byte_array_from_c_string("int_parameter_key");
        const int intParamValue = 35777;
        VirgilByteArray strParamKey = virgil_byte_array_from_c_string("string_parameter_key");
        VirgilByteArray strParamValue = virgil_byte_array_from_c_string("string parameter");
        VirgilByteArray hexParamKey = virgil_byte_array_from_c_string("data_param_value");
        VirgilByteArray hexParamValue = virgil_byte_array_from_c_string("will be stored as octet string");

        cipher.customParameters().setInteger(intParamKey, intParamValue);
        cipher.customParameters().setString(strParamKey, strParamValue);
        cipher.customParameters().setData(hexParamKey, hexParamValue);

        VirgilByteArray encryptedData = cipher.encrypt(testData, false);
        VirgilByteArray contentInfo = cipher.getContentInfo();
        REQUIRE(contentInfo.size() > 0);

        REQUIRE_NOTHROW(
            cipher.setContentInfo(contentInfo)
        );

        VirgilByteArray decryptedData;
        REQUIRE_NOTHROW(
            decryptedData = cipher.decryptWithKey(encryptedData, certificateId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(cipher.customParameters().getInteger(intParamKey) == intParamValue);
        REQUIRE(cipher.customParameters().getString(strParamKey) == strParamValue);
        REQUIRE(cipher.customParameters().getData(hexParamKey) == hexParamValue);
    }
}

TEST_CASE("encrypt and decrypt with password", "[cipher]") {
    VirgilByteArray password = virgil_byte_array_from_c_string("password");
    VirgilByteArray wrongPassword = virgil_byte_array_from_c_string("wrong password");
    VirgilByteArray testData = virgil_byte_array_from_c_string("this string will be encrypted");

    VirgilCipher cipher;
    cipher.addPasswordRecipient(password);

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
            decryptedData = cipher.decryptWithPassword(encryptedData, wrongPassword)
        );
        REQUIRE_NOTHROW(
            decryptedData = cipher.decryptWithPassword(encryptedData, password)
        );
        REQUIRE(testData == decryptedData);
    }
}