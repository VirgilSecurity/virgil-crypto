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
 * @file test_key_pair.cxx
 * @brief Covers class VirgilKeyPair
 */

#include "catch.hpp"
#include "rsa_keys.h"
#include "deterministic_keys.h"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilCipher;

static const char* const kPrivateKey =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBDXDqM+Uj5o3+7pa2Xo\n"
                "6PAkAgIWojAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEELDgwtEuhySH70wD6RFI\n"
                "G3EEQBNKQxiwmOrX8vsFmLQfhu5momj7hEQ8WZhu4LEmnVbsXJKcxOUX6QCU1QH/\n"
                "OzbvnCIlAWTCxCdzkqYuelBnNac=\n"
                "-----END ENCRYPTED PRIVATE KEY-----\n";


static const char* const kPrivateKeyPwd = "strong_pwd";

static const char kPublicKeyPEM[] =
        "-----BEGIN PUBLIC KEY-----\n"
                "MCowBQYDK2VwAyEAg4boYkLfd4NRIQeDPfL8+73qk098mKXNerM9Qjpo9iY=\n"
                "-----END PUBLIC KEY-----\n";

static const char kPrivateKeyPEM[] =
        "-----BEGIN PRIVATE KEY-----\n"
                "MC4CAQAwBQYDK2VwBCIEIEJXChwWLuA0M3jgyhzic6BXD248kBRANysvBBI3d1/G\n"
                "-----END PRIVATE KEY-----\n";

static const char kPublicKeyDER[] =
        "302a300506032b65700321008386e86242df7783512107833df2fcfbbdea934f7c98a5cd7ab33d423a68f626";

static const char kPrivateKeyDER[] =
        "302e020100300506032b65700422042042570a1c162ee0343378e0ca1ce273a0570f6e3c901440372b2f041237775fc6";


TEST_CASE("Reset Private Key password", "[key-pair]") {
    VirgilByteArray oldPwd = VirgilByteArrayUtils::stringToBytes(kPrivateKeyPwd);
    VirgilByteArray newPwd = VirgilByteArrayUtils::stringToBytes("new password");
    VirgilByteArray emptyPwd;

    VirgilByteArray initialPrivateKey = VirgilByteArrayUtils::stringToBytes(kPrivateKey);
    VirgilByteArray newPrivateKey = VirgilKeyPair::resetPrivateKeyPassword(initialPrivateKey, oldPwd, newPwd);
    VirgilByteArray oldPrivateKey = VirgilKeyPair::resetPrivateKeyPassword(newPrivateKey, newPwd, oldPwd);

    VirgilByteArray newPrivateKeyNoPassword =
            VirgilKeyPair::resetPrivateKeyPassword(newPrivateKey, newPwd, emptyPwd);

    VirgilByteArray oldPrivateKeyNoPassword =
            VirgilKeyPair::resetPrivateKeyPassword(oldPrivateKey, oldPwd, emptyPwd);

    REQUIRE(VirgilByteArrayUtils::bytesToString(newPrivateKeyNoPassword) ==
            VirgilByteArrayUtils::bytesToString(oldPrivateKeyNoPassword));
}

TEST_CASE("Generate ephemeral key pair and compute shared", "[key-pair]") {

    SECTION("with plain private key") {
        VirgilKeyPair donorPair = VirgilKeyPair::generate(VirgilKeyPair::Type::FAST_EC_X25519);

        VirgilKeyPair ephemeralKeyPair = VirgilKeyPair::generateFrom(donorPair);

        VirgilByteArray sharedEphemeral;
        REQUIRE_NOTHROW(
                sharedEphemeral = VirgilCipher::computeShared(donorPair.publicKey(), ephemeralKeyPair.privateKey()));

        VirgilByteArray sharedDonor;
        REQUIRE_NOTHROW(
                sharedDonor = VirgilCipher::computeShared(ephemeralKeyPair.publicKey(), donorPair.privateKey()));

        REQUIRE(sharedDonor == sharedEphemeral);
    }

    SECTION("with encrypted private key") {
        VirgilByteArray donorKeyPassword = VirgilByteArrayUtils::stringToBytes("donor password");
        VirgilKeyPair donorPair = VirgilKeyPair::generate(VirgilKeyPair::Type::EC_BP256R1, donorKeyPassword);

        VirgilByteArray ephemeralKeyPassword = VirgilByteArrayUtils::stringToBytes("ephemeral password");
        VirgilKeyPair ephemeralKeyPair = VirgilKeyPair::generateFrom(donorPair, donorKeyPassword, ephemeralKeyPassword);

        VirgilByteArray sharedEphemeral;
        REQUIRE_NOTHROW(
                sharedEphemeral = VirgilCipher::computeShared(donorPair.publicKey(), ephemeralKeyPair.privateKey(),
                        ephemeralKeyPassword));

        VirgilByteArray sharedDonor;
        REQUIRE_NOTHROW(
                sharedDonor = VirgilCipher::computeShared(ephemeralKeyPair.publicKey(), donorPair.privateKey(),
                        donorKeyPassword));

        REQUIRE(sharedDonor == sharedEphemeral);
    }
}

TEST_CASE("Extract public key from private key", "[key-pair]") {
    VirgilByteArray privateKey = VirgilByteArrayUtils::stringToBytes(kPrivateKey);
    VirgilByteArray privateKeyPassword = VirgilByteArrayUtils::stringToBytes(kPrivateKeyPwd);
    VirgilByteArray publicKey = VirgilKeyPair::extractPublicKey(privateKey, privateKeyPassword);
    REQUIRE(VirgilKeyPair::isKeyPairMatch(publicKey, privateKey, privateKeyPassword));
}

TEST_CASE("Generate private key with long password", "[key-pair]") {
    VirgilByteArray keyPassword = VirgilByteArrayUtils::stringToBytes(
            "m5I&8~@Rohh+7B0-iL`Sf6Se\"7A=8i!oQhIDNhk,q25RwoY2vF"
                    "Lrx8XJ0]WIO5k#B=liHk&!iTj,42CsBrt|UePW*753r^w\"X06p"
                    "EoJ,2DIj{rfrZ2c]1L!L_45[]1KPGY6Mqy-jFY3Q$5PHkFKx5("
                    "yR$N5B,MC#]6Rw3C]q1;-xs33szYC5XDk#YvP=mhnN7kgPp4}0"
                    "PtImqC2mT#=M85axZw8cPo6TUD0Ba,_HN^5E4v`R\"@8e>Xp]y6"
                    "X&#8g0~FHG5qFI67&PM`3u8{>lVxZ7!q-t9jVUHcv|d3OGxpxB"
    );
    VirgilKeyPair keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type::FAST_EC_X25519, keyPassword);
    REQUIRE(VirgilKeyPair::isKeyPairMatch(keyPair.publicKey(), keyPair.privateKey(), keyPassword));
}


TEST_CASE("Encrypt/Decrypt Private Key", "[key-pair]") {
    VirgilByteArray keyPwd = VirgilByteArrayUtils::stringToBytes("key password");
    VirgilByteArray wrongKeyPwd = VirgilByteArrayUtils::stringToBytes("wrong key password");

    VirgilByteArray initialPrivateKey = VirgilKeyPair::generateRecommended().privateKey();
    VirgilByteArray encryptedPrivateKey = VirgilKeyPair::encryptPrivateKey(initialPrivateKey, keyPwd);
    VirgilByteArray decryptedPrivateKey = VirgilKeyPair::decryptPrivateKey(encryptedPrivateKey, keyPwd);

    REQUIRE(VirgilByteArrayUtils::bytesToString(initialPrivateKey) ==
            VirgilByteArrayUtils::bytesToString(decryptedPrivateKey));

    REQUIRE_THROWS(VirgilKeyPair::encryptPrivateKey(initialPrivateKey, VirgilByteArray()));
    REQUIRE_THROWS(VirgilKeyPair::decryptPrivateKey(encryptedPrivateKey, wrongKeyPwd));
}

TEST_CASE("Export Public Key", "[key-pair]") {
    VirgilByteArray basePublicKeyPEM = VirgilByteArrayUtils::stringToBytes(kPublicKeyPEM);
    VirgilByteArray basePublicKeyDER = VirgilByteArrayUtils::hexToBytes(kPublicKeyDER);

    SECTION("to DER format") {
        VirgilByteArray publicKeyDER = VirgilKeyPair::publicKeyToDER(basePublicKeyPEM);
        REQUIRE(kPublicKeyDER == VirgilByteArrayUtils::bytesToHex(publicKeyDER));
    }

    SECTION("to PEM format") {
        VirgilByteArray publicKeyPEM = VirgilKeyPair::publicKeyToPEM(basePublicKeyDER);
        REQUIRE(kPublicKeyPEM == VirgilByteArrayUtils::bytesToString(publicKeyPEM));
    }
}

TEST_CASE("Export Private Key", "[key-pair]") {
    VirgilByteArray basePrivateKeyPEM = VirgilByteArrayUtils::stringToBytes(kPrivateKeyPEM);
    VirgilByteArray basePrivateKeyDER = VirgilByteArrayUtils::hexToBytes(kPrivateKeyDER);

    SECTION("to DER format") {
        VirgilByteArray privateKeyDER = VirgilKeyPair::privateKeyToDER(basePrivateKeyPEM);
        REQUIRE(kPrivateKeyDER == VirgilByteArrayUtils::bytesToHex(privateKeyDER));
    }

    SECTION("to PEM format") {
        VirgilByteArray privateKeyPEM = VirgilKeyPair::privateKeyToPEM(basePrivateKeyDER);
        REQUIRE(kPrivateKeyPEM == VirgilByteArrayUtils::bytesToString(privateKeyPEM));
    }
}

TEST_CASE("Export keys RSA", "[key-pair]") {

    SECTION("4096 encrypted") {

        SECTION("to DER format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Private),
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Password)
            ));
        }

        SECTION("to PEM format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Private),
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Password)
            ));
        }
    }

    SECTION("4096 plain") {

        SECTION("to DER format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Private_Plain)
            ));
        }

        SECTION("to PEM format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_4096_Private_Plain)
            ));
        }
    }

    SECTION("8192 encrypted") {

        SECTION("to DER format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Private),
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Password)
            ));
        }

        SECTION("to PEM format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Private),
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Password)
            ));
        }
    }

    SECTION("8192 plain") {

        SECTION("to DER format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToDER(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Private_Plain)
            ));
        }

        SECTION("to PEM format") {
            REQUIRE_NOTHROW(VirgilKeyPair::publicKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Public)
            ));

            REQUIRE_NOTHROW(VirgilKeyPair::privateKeyToPEM(
                VirgilByteArrayUtils::stringToBytes(kRSA_8192_Private_Plain)
            ));
        }
    }
}

TEST_CASE("Generate Deterministic Key Pair", "[key-pair]") {
    VirgilByteArray strongKeyMaterial = VirgilByteArrayUtils::hexToBytes(kDeterministic_KeyMaterial);

    SECTION("check FAST_EC_ED25519") {
        VirgilKeyPair keyPair(VirgilByteArray{}, VirgilByteArray{});

        REQUIRE_NOTHROW(keyPair = VirgilKeyPair::generateFromKeyMaterial(
                VirgilKeyPair::Algorithm::FAST_EC_ED25519, strongKeyMaterial));
        REQUIRE(kDeterministic_FAST_EC_ED25519_Public == VirgilByteArrayUtils::bytesToString(keyPair.publicKey()));
        REQUIRE(kDeterministic_FAST_EC_ED25519_Private == VirgilByteArrayUtils::bytesToString(keyPair.privateKey()));
    }
}
