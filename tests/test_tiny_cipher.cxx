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
 * @file test_tiny_cipher.cxx
 * @brief Covers class VirgilTinyCipher
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilTinyCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilCryptoException.h>

#include <iostream>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilTinyCipher;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilCryptoException;

static void test_encrypt_decrypt(const VirgilKeyPair& keyPair, const VirgilByteArray& keyPassword) {
    VirgilByteArray testData = VirgilByteArrayUtils::stringToBytes("this string will be encrypted and decrypted");

    VirgilTinyCipher encCipher;
    VirgilTinyCipher decCipher;
    VirgilByteArray decryptedData;

    SECTION("without signature - OK") {
        encCipher.encrypt(testData, keyPair.publicKey());

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            decCipher.addPackage(encCipher.getPackage(i));
        }
        REQUIRE(decCipher.isPackagesAccumulated());
        REQUIRE_NOTHROW(decryptedData = decCipher.decrypt(keyPair.privateKey(), keyPassword));
        REQUIRE(decryptedData == testData);
    }

    SECTION("with signature - OK") {
        encCipher.encryptAndSign(testData, keyPair.publicKey(), keyPair.privateKey(), keyPassword);

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            decCipher.addPackage(encCipher.getPackage(i));
        }
        REQUIRE(decCipher.isPackagesAccumulated());
        REQUIRE_NOTHROW(
                decryptedData = decCipher.verifyAndDecrypt(keyPair.publicKey(), keyPair.privateKey(), keyPassword));
        REQUIRE(decryptedData == testData);
    }

    SECTION("without signature - malformed header in the master package") {
        encCipher.encrypt(testData, keyPair.publicKey());

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            if (i == 0) {
                VirgilByteArray malformedPackage = encCipher.getPackage(i);
                malformedPackage[0] |= 0xFF;
                REQUIRE_THROWS(decCipher.addPackage(malformedPackage));
            } else {
                decCipher.addPackage(encCipher.getPackage(i));
            }
        }
        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        REQUIRE_THROWS(decryptedData = decCipher.decrypt(keyPair.privateKey(), keyPassword));
    }

    SECTION("without signature - malformed body in the master package") {
        encCipher.encrypt(testData, keyPair.publicKey());

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            if (i == 0) {
                VirgilByteArray malformedPackage = encCipher.getPackage(i);
                malformedPackage[3] |= 0xFF;
                malformedPackage[4] |= 0xBB;
                REQUIRE_NOTHROW(decCipher.addPackage(malformedPackage));
            } else {
                decCipher.addPackage(encCipher.getPackage(i));
            }
        }
        REQUIRE(decCipher.isPackagesAccumulated());
        REQUIRE_THROWS(decryptedData = decCipher.decrypt(keyPair.privateKey(), keyPassword));
    }

    SECTION("with signature - malformed header in the data package") {
        encCipher.encryptAndSign(testData, keyPair.publicKey(), keyPair.privateKey(), keyPassword);

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            if (i != 0) {
                VirgilByteArray malformedPackage = encCipher.getPackage(i);
                malformedPackage[0] |= 0xFF;
                REQUIRE_THROWS(decCipher.addPackage(malformedPackage));
            } else {
                decCipher.addPackage(encCipher.getPackage(i));
            }
        }
        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        REQUIRE_THROWS(
                decryptedData = decCipher.verifyAndDecrypt(keyPair.publicKey(), keyPair.privateKey(), keyPassword));
    }

    SECTION("with signature - malformed body in the data package") {
        encCipher.encryptAndSign(testData, keyPair.publicKey(), keyPair.privateKey(), keyPassword);

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            if (i != 0) {
                VirgilByteArray malformedPackage = encCipher.getPackage(i);
                malformedPackage[3] |= 0xFF;
                malformedPackage[4] |= 0xBB;
                REQUIRE_NOTHROW(decCipher.addPackage(malformedPackage));
            } else {
                decCipher.addPackage(encCipher.getPackage(i));
            }
        }
        REQUIRE(decCipher.isPackagesAccumulated());
        REQUIRE_THROWS(
                decryptedData = decCipher.verifyAndDecrypt(keyPair.publicKey(), keyPair.privateKey(), keyPassword));
    }
}


#define TEST_CASE_ENCRYPT_DECRYPT(KeyType) \
    TEST_CASE("VirgilTinyCipher: encrypt and decrypt with " #KeyType " keys", "[tiny-cipher]") { \
        const VirgilByteArray keyPassword = VirgilByteArrayUtils::stringToBytes("key keyPassword"); \
        test_encrypt_decrypt(VirgilKeyPair::generate(VirgilKeyPair::Type::KeyType, keyPassword), keyPassword); \
    }

TEST_CASE_ENCRYPT_DECRYPT(FAST_EC_ED25519)

#undef TEST_CASE_ENCRYPT_DECRYPT
