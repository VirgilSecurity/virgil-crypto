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
 * @file test_cipher.cxx
 * @brief Covers class VirgilCipher
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::str2bytes;
using virgil::crypto::bytes2hex;
using virgil::crypto::bytes2str;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipher;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilByteArrayUtils;

constexpr char kRSA_8192_Public[] = "-----BEGIN PUBLIC KEY-----\n"
        "MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAtWIfF94niOYRV8JKvX9C\n"
        "RzlxWCeGyv6RNTma1zRZq2lKHBFc+5j5I4eqPPVQ4Xfb4fVkB/Vua1zLSRT49G8X\n"
        "f/9KvfavHUZG/8ft2VzyAIuxmVbSt1UToOGut/kCsstFQkC0X7Jny66ETh6inV4k\n"
        "/BiVYm1hJCap/k6o7briD8vayKrzPpzK2LRVnFDiVjreFNI2aoUDQhWbdSSOQdI4\n"
        "FJWuYypgOWnZWcCIOtCG7s5D9HONlFR/C011AQekrB3e0rxMMlp6s2IH+9PSmHml\n"
        "FkgDX8Jn5CfkpQbT0CTEvVnfcb7/RbX+gxsvDO3HRL6Fzhzo/uliwNa0rbAzWYid\n"
        "BamWCXsox8z1Cfd4VMf70FnRPgLLoeQk0LulFwbzZZSfi16lMaAtTcnj9GI0dlZY\n"
        "0e83kZDHP/Udrq/FqCvOeIYeRZAvq5mRtPuGvqr0wR0owgZaPg4lf+IoBlj/JAJR\n"
        "UjUSty1LLfR/1p0I0rntzzHyQfWJa6MQi9e4n1zvK5TITnK7iRm5zAOm7SYWNs8H\n"
        "PMuCNtTOidt1pyaU9wpZZ+3BPM8CYTy89QNi9tUfv2+QqaA1OHjf519Tb4zgJZTl\n"
        "1SnDYzG8HNyVu+R083NnpPMedmGsLI09GvjWtkW3imrGk//Ll9e92Wxb2/8qB8Db\n"
        "PnPh5JI5SWrvY5fcEVsv7jTEsM2FlCg/hFXkIwMmwt9PLKMESpCxP39ldX7lCayo\n"
        "vNlpJzK82alLPttgarP0YX3rwEUVEURUPhwYF7j5IiVxRl5HumuRXP0bHexn1aJ0\n"
        "obuAM1mhC/9v6w0dFJiptbIp2DrdKC80BnWQZpXzxfxcCMvOlP1SuSZCQ7e2c82X\n"
        "34UWUXIiGRszdFCL/Y6Zvaz5OF425Tuh86+mK3zZ8hX1+1UYFmhRsCRkEwYOAs4W\n"
        "3tn+rSU01XNByWxWb1pxCSjntVNZQgeqOgDVMXihzwxMtBa/C9LiPNKzSlmQIOg2\n"
        "g599d4LyAAPExevRVDb7eRmZEGZzQl/ve4VjzjpqynDUfvQG6ABXy4OMcWEo5byG\n"
        "AsRByR288yQzEPxW6+GtwVubAy/0EP6PqM3Vu4BiKZcHJkcFYyRvNY2i0MI5Nibx\n"
        "rm94mgmJYw9kPU/RvOSRYGmdhhZaY3hQJPf0wTUphKLPJ3BxxzT8dIsRLeL+xPVD\n"
        "+9okwQ5OiuPG6iCT758fc5DVQYmyvwZMwmPzqp7RlaoFT0VYcv+0WDBUnC+6R+SU\n"
        "RQ9b0oS/9eRLq4uhJgkYFmyU5FhFAwXoQjtm5b2i+xJ1ctVmNUwh5f6hoJcmx/KP\n"
        "SOLk5teZy4WK9p5APVI8ApwwvJH2gs0qohIjFT4H6vppaK/K5XVMvZYech/237gz\n"
        "8wIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kRSA_8192_Private[] = "-----BEGIN RSA PRIVATE KEY-----\n"
        "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\n"
        "-----END RSA PRIVATE KEY-----\n";

TEST_CASE("encrypt and decrypt with generated keys", "[cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair(password);

    VirgilCipher cipher;
    cipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey())
        );
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), password)
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

        cipher.customParams().setInteger(intParamKey, intParamValue);
        cipher.customParams().setString(strParamKey, strParamValue);
        cipher.customParams().setData(hexParamKey, hexParamValue);

        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        cipher.removeAllRecipients();
        cipher.customParams().clear();

        VirgilByteArray decryptedData;
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(cipher.customParams().getInteger(intParamKey) == intParamValue);
        REQUIRE(cipher.customParams().getString(strParamKey) == strParamValue);
        REQUIRE(cipher.customParams().getData(hexParamKey) == hexParamValue);
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
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey())
        );
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), password)
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

        cipher.customParams().setInteger(intParamKey, intParamValue);
        cipher.customParams().setString(strParamKey, strParamValue);
        cipher.customParams().setData(hexParamKey, hexParamValue);

        VirgilByteArray encryptedData = cipher.encrypt(testData, false);
        VirgilByteArray contentInfo = cipher.getContentInfo();
        REQUIRE(contentInfo.size() > 0);

        REQUIRE_NOTHROW(
                cipher.setContentInfo(contentInfo)
        );

        VirgilByteArray decryptedData;
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(cipher.customParams().getInteger(intParamKey) == intParamValue);
        REQUIRE(cipher.customParams().getString(strParamKey) == strParamValue);
        REQUIRE(cipher.customParams().getData(hexParamKey) == hexParamValue);
    }
}

TEST_CASE("generated keys", "[cipher]") {
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray bobId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilByteArray johnId = str2bytes("968dc52d-2045-4abe-ab51-0b04737cac76");
    VirgilKeyPair bobKeyPair;
    VirgilKeyPair johnKeyPair;
    VirgilByteArray alicePassword = str2bytes("alice secret");

    SECTION("encrypt for multiple recipients") {
        VirgilByteArray encryptedData;

        VirgilCipher cipher;
        cipher.addKeyRecipient(bobId, bobKeyPair.publicKey());
        cipher.addKeyRecipient(johnId, johnKeyPair.publicKey());
        cipher.addPasswordRecipient(alicePassword);
        encryptedData = cipher.encrypt(testData, true);

        SECTION("decrypt for Bob") {
            VirgilCipher decoder;
            VirgilByteArray decryptedData = decoder.decryptWithKey(encryptedData, bobId, bobKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for John") {
            VirgilCipher decoder;
            VirgilByteArray decryptedData = decoder.decryptWithKey(encryptedData, johnId, johnKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for Alice") {
            VirgilCipher decoder;
            VirgilByteArray decryptedData = decoder.decryptWithPassword(encryptedData, alicePassword);
            REQUIRE(testData == decryptedData);
        }
    }
}

TEST_CASE("encrypt and decrypt with password", "[cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray wrongPassword = str2bytes("wrong password");
    VirgilByteArray testData = str2bytes("this string will be encrypted");

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

TEST_CASE("encrypt and decrypt RSA-3072", "[cipher-rsa]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_RSA_3072, password);

    VirgilCipher cipher;
    cipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey())
        );
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), password)
        );
        REQUIRE(testData == decryptedData);
    }
}

TEST_CASE("encrypt and decrypt RSA-8192", "[cipher-rsa]") {
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair(VirgilByteArrayUtils::stringToBytes(kRSA_8192_Public),
            VirgilByteArrayUtils::stringToBytes(kRSA_8192_Private));

    VirgilCipher cipher;
    cipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey());
        REQUIRE(testData == decryptedData);
    }
}

TEST_CASE("encrypt and decrypt curve25519", "[cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_EC_M255);

    VirgilCipher cipher;
    cipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), password);
        REQUIRE(testData == decryptedData);
    }
}

TEST_CASE("check recipient existence", "[cipher]") {
    VirgilByteArray bobId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilByteArray johnId = str2bytes("968dc52d-2045-4abe-ab51-0b04737cac76");
    VirgilByteArray aliceId = str2bytes("99e435e7-2527-4a5a-89bb-37927bdb337b");
    VirgilKeyPair bobKeyPair;
    VirgilKeyPair johnKeyPair;

    VirgilCipher cipher;
    cipher.addKeyRecipient(bobId, bobKeyPair.publicKey());
    cipher.addKeyRecipient(johnId, johnKeyPair.publicKey());

    SECTION("within local context") {
        REQUIRE(cipher.keyRecipientExists(bobId));
        REQUIRE(cipher.keyRecipientExists(johnId));
        REQUIRE_FALSE(cipher.keyRecipientExists(aliceId));
    }

    SECTION("ContentInfo context") {
        (void) cipher.encrypt(VirgilByteArray());

        VirgilCipher restoredCipher;
        restoredCipher.setContentInfo(cipher.getContentInfo());

        REQUIRE(restoredCipher.keyRecipientExists(bobId));
        REQUIRE(restoredCipher.keyRecipientExists(johnId));
        REQUIRE_FALSE(restoredCipher.keyRecipientExists(aliceId));
    }
}
