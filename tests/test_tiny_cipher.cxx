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
 * @file test_tiny_cipher.cxx
 * @brief Covers class VirgilTinyCipher
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilTinyCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilTinyCipher;
using virgil::crypto::VirgilKeyPair;

TEST_CASE("VirgilTinyCipher: encrypt and decrypt with generated keys", "[tiny-cipher]") {
    VirgilByteArray password = VirgilByteArrayUtils::stringToBytes("password");
    VirgilByteArray testData = VirgilByteArrayUtils::stringToBytes("this string will be encrypted and decrypted");

    VirgilTinyCipher encCipher;
    VirgilTinyCipher decCipher;
    VirgilByteArray decryptedData;

    SECTION("Curve25519 without sign - OK") {
        VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_EC_Curve25519, password);
        encCipher.encrypt(testData, keyPair.publicKey());

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            decCipher.addPackage(encCipher.getPackage(i));
        }
        REQUIRE(decCipher.isPackagesAccumulated());
        REQUIRE_NOTHROW(decryptedData = decCipher.decrypt(keyPair.privateKey(), password));
        REQUIRE(decryptedData == testData);
    }

    SECTION("Curve25519 with sign - OK") {
        VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_EC_Curve25519, password);
        encCipher.encryptAndSign(testData, keyPair.publicKey(), keyPair.privateKey(), password);

        REQUIRE_FALSE(decCipher.isPackagesAccumulated());
        for (size_t i = 0; i < encCipher.getPackageCount(); ++i) {
            decCipher.addPackage(encCipher.getPackage(i));
        }
        REQUIRE(decCipher.isPackagesAccumulated());
        REQUIRE_NOTHROW(
                decryptedData = decCipher.verifyAndDecrypt(keyPair.publicKey(), keyPair.privateKey(), password));
        REQUIRE(decryptedData == testData);
    }

    SECTION("Curve25519 without sign - malformed header in the master package") {
        VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_EC_Curve25519, password);
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
        REQUIRE_THROWS(decryptedData = decCipher.decrypt(keyPair.privateKey(), password));
    }

    SECTION("Curve25519 without sign - malformed body in the master package") {
        VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_EC_Curve25519, password);
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
        REQUIRE_THROWS(decryptedData = decCipher.decrypt(keyPair.privateKey(), password));
    }

    SECTION("Curve25519 with sign - malformed header in the data package") {
            VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_EC_Curve25519, password);
            encCipher.encryptAndSign(testData, keyPair.publicKey(), keyPair.privateKey(), password);

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
                    decryptedData = decCipher.verifyAndDecrypt(keyPair.publicKey(), keyPair.privateKey(), password));
    }

    SECTION("Curve25519 with sign - malformed body in the data package") {
            VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_EC_Curve25519, password);
            encCipher.encryptAndSign(testData, keyPair.publicKey(), keyPair.privateKey(), password);

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
                    decryptedData = decCipher.verifyAndDecrypt(keyPair.publicKey(), keyPair.privateKey(), password));
    }

}
