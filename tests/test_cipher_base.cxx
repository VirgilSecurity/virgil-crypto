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
 * @file test_cipher_base.cxx
 * @brief Covers class VirgilCipherBase.
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCipherBase.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCipherBase;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::VirgilKeyPair;

constexpr char kPublicKey[] =
        "-----BEGIN PUBLIC KEY-----\n"
                "MFswFQYHKoZIzj0CAQYKKwYBBAGXVQEFAQNCAARhEuj2bVQKPe1ZXst7ubob+bVr\n"
                "9tcjPs7x7mVumQO7YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                "-----END PUBLIC KEY-----\n";

constexpr char kPrivateKey[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
                "MHkCAQEEIEShP488iU1wuJLX6t8tx8hTbi/vYJPLWiE9xSIn3bEooAwGCisGAQQB\n"
                "l1UBBQGhRANCAARhEuj2bVQKPe1ZXst7ubob+bVr9tcjPs7x7mVumQO7YAAAAAAA\n"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                "-----END EC PRIVATE KEY-----";

constexpr char kUnsupportedPublicKey[] =
        "-----BEGIN PUBLIC KEY-----\n"
                "MFswFQYHKoZIzj0CAQYKKwYBBAGXVQEFAgNCAARhEuj2bVQKPe1ZXst7ubob+bVr\n"
                "9tcjPs7x7mVumQO7YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                "-----END PUBLIC KEY-----\n";


TEST_CASE("VirgilCipherBase::addKeyRecipient()", "[cipher-base]") {
    const VirgilByteArray emptyRecipientId = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray invalidPublicKey = VirgilByteArrayUtils::stringToBytes("invalid public key");
    const VirgilByteArray unsupportedPublicKey = VirgilByteArrayUtils::stringToBytes(kUnsupportedPublicKey);
    const VirgilByteArray emptyPublicKey = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray validRecipientId = VirgilByteArrayUtils::stringToBytes("valid-bob-id");
    const VirgilByteArray validPublicKey = VirgilByteArrayUtils::stringToBytes(kPublicKey);

    VirgilCipherBase cipherBase;

    SECTION("Add recipient with valid parameters") {
        REQUIRE_NOTHROW(cipherBase.addKeyRecipient(validRecipientId, validPublicKey));
    }

    SECTION("Add recipient with invalid parameter: recipientId") {
        REQUIRE_THROWS_AS(cipherBase.addKeyRecipient(emptyRecipientId, validPublicKey), VirgilCryptoException);
    }

    SECTION("Add recipient with empty parameter: publicKey") {
        REQUIRE_THROWS_AS(cipherBase.addKeyRecipient(validRecipientId, emptyPublicKey), VirgilCryptoException);
    }

    SECTION("Add recipient with invalid format of parameter: publicKey") {
        REQUIRE_THROWS_AS(cipherBase.addKeyRecipient(validRecipientId, invalidPublicKey), VirgilCryptoException);
    }

    SECTION("Add recipient with unsupported algorithm defined with parameter: publicKey") {
        REQUIRE_THROWS_AS(cipherBase.addKeyRecipient(validRecipientId, unsupportedPublicKey), VirgilCryptoException);
    }
}

TEST_CASE("VirgilCipherBase::removeKeyRecipient()", "[cipher-base]") {
    const VirgilByteArray emptyRecipientId = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray existingRecipientId = VirgilByteArrayUtils::stringToBytes("valid-bob-id");
    const VirgilByteArray nonExistingRecipientId = VirgilByteArrayUtils::stringToBytes("valid-alice-id");
    const VirgilByteArray validPublicKey = VirgilByteArrayUtils::stringToBytes(kPublicKey);

    VirgilCipherBase cipherBase;
    cipherBase.addKeyRecipient(existingRecipientId, validPublicKey);

    SECTION("Remove existing recipient") {
        REQUIRE_NOTHROW(cipherBase.removeKeyRecipient(existingRecipientId));
    }

    SECTION("Remove non existing recipient") {
        REQUIRE_NOTHROW(cipherBase.removeKeyRecipient(nonExistingRecipientId));
    }

    SECTION("Remove empty recipient") {
        REQUIRE_NOTHROW(cipherBase.removeKeyRecipient(emptyRecipientId));
    }
}

TEST_CASE("VirgilCipherBase::keyRecipientExists()", "[cipher-base]") {
    const VirgilByteArray emptyRecipientId = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray existingRecipientId = VirgilByteArrayUtils::stringToBytes("valid-bob-id");
    const VirgilByteArray nonExistingRecipientId = VirgilByteArrayUtils::stringToBytes("valid-alice-id");
    const VirgilByteArray validPublicKey = VirgilByteArrayUtils::stringToBytes(kPublicKey);

    VirgilCipherBase cipherBase;
    REQUIRE_NOTHROW(cipherBase.addKeyRecipient(existingRecipientId, validPublicKey));

    SECTION("Check existing recipient") {
        REQUIRE(cipherBase.keyRecipientExists(existingRecipientId));
    }

    SECTION("Check non existing recipient") {
        REQUIRE_FALSE(cipherBase.keyRecipientExists(nonExistingRecipientId));
    }

    SECTION("Check empty recipient") {
        REQUIRE_FALSE(cipherBase.keyRecipientExists(emptyRecipientId));
    }
}

TEST_CASE("VirgilCipherBase::addPasswordRecipient()", "[cipher-base]") {
    const VirgilByteArray emptyPassword = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray validPassword = VirgilByteArrayUtils::stringToBytes("valid-bob-password");

    VirgilCipherBase cipherBase;

    SECTION("Add non empty password recipient") {
        REQUIRE_NOTHROW(cipherBase.addPasswordRecipient(validPassword));
    }

    SECTION("Add non empty password recipient twice") {
        REQUIRE_NOTHROW(cipherBase.addPasswordRecipient(validPassword));
        REQUIRE_NOTHROW(cipherBase.addPasswordRecipient(validPassword));
    }

    SECTION("Add empty password recipient") {
        REQUIRE_THROWS_AS(cipherBase.addPasswordRecipient(emptyPassword), VirgilCryptoException);
    }
}

TEST_CASE("VirgilCipherBase::removePasswordRecipient()", "[cipher-base]") {
    const VirgilByteArray emptyPassword = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray existingPassword = VirgilByteArrayUtils::stringToBytes("valid-bob-password");
    const VirgilByteArray nonExistingPassword = VirgilByteArrayUtils::stringToBytes("valid-alice-password");

    VirgilCipherBase cipherBase;

    REQUIRE_NOTHROW(cipherBase.addPasswordRecipient(existingPassword));


    SECTION("Remove existing password recipient") {
        REQUIRE_NOTHROW(cipherBase.removePasswordRecipient(existingPassword));
    }

    SECTION("Remove existing password recipient twice") {
        REQUIRE_NOTHROW(cipherBase.removePasswordRecipient(existingPassword));
        REQUIRE_NOTHROW(cipherBase.removePasswordRecipient(existingPassword));
    }

    SECTION("Remove non existing password recipient") {
        REQUIRE_NOTHROW(cipherBase.removePasswordRecipient(nonExistingPassword));
    }

    SECTION("Remove empty password recipient") {
        REQUIRE_NOTHROW(cipherBase.removePasswordRecipient(emptyPassword));
    }
}

TEST_CASE("VirgilCipherBase::passwordRecipientExists()", "[cipher-base]") {
    const VirgilByteArray emptyPassword = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray existingPassword = VirgilByteArrayUtils::stringToBytes("valid-bob-password");
    const VirgilByteArray nonExistingPassword = VirgilByteArrayUtils::stringToBytes("valid-alice-password");

    VirgilCipherBase cipherBase;

    REQUIRE_NOTHROW(cipherBase.addPasswordRecipient(existingPassword));

    SECTION("Check existing recipient") {
        REQUIRE(cipherBase.passwordRecipientExists(existingPassword));
    }

    SECTION("Check non existing recipient") {
        REQUIRE_FALSE(cipherBase.passwordRecipientExists(nonExistingPassword));
    }

    SECTION("Check empty recipient") {
        REQUIRE_FALSE(cipherBase.passwordRecipientExists(emptyPassword));
    }
}

TEST_CASE("VirgilCipherBase::removeAllRecipients()", "[cipher-base]") {
    const VirgilByteArray existingPassword = VirgilByteArrayUtils::stringToBytes("valid-bob-password");
    const VirgilByteArray existingRecipientId = VirgilByteArrayUtils::stringToBytes("valid-bob-id");
    const VirgilByteArray validPublicKey = VirgilByteArrayUtils::stringToBytes(kPublicKey);

    VirgilCipherBase cipherBase;

    REQUIRE_NOTHROW(cipherBase.addPasswordRecipient(existingPassword));
    REQUIRE_NOTHROW(cipherBase.addKeyRecipient(existingRecipientId, validPublicKey));

    SECTION("Remove all recipients") {
        REQUIRE(cipherBase.keyRecipientExists(existingRecipientId));
        REQUIRE(cipherBase.passwordRecipientExists(existingPassword));
        REQUIRE_NOTHROW(cipherBase.removeAllRecipients());
        REQUIRE_FALSE(cipherBase.passwordRecipientExists(existingPassword));
        REQUIRE_FALSE(cipherBase.keyRecipientExists(existingPassword));
    }

    SECTION("Remove all recipients twice") {
        REQUIRE(cipherBase.keyRecipientExists(existingRecipientId));
        REQUIRE(cipherBase.passwordRecipientExists(existingPassword));
        REQUIRE_NOTHROW(cipherBase.removeAllRecipients());
        REQUIRE_NOTHROW(cipherBase.removeAllRecipients());
        REQUIRE_FALSE(cipherBase.passwordRecipientExists(existingPassword));
        REQUIRE_FALSE(cipherBase.keyRecipientExists(existingPassword));
    }
}

TEST_CASE("VirgilCipherBase::getContentInfo()", "[cipher-base]") {
    VirgilCipherBase cipherBase;
    SECTION("Read empty content info") {
        VirgilByteArray contentInfo;
        REQUIRE_THROWS_AS(contentInfo = cipherBase.getContentInfo(), VirgilCryptoException);
    }
}

TEST_CASE("VirgilCipherBase::setContentInfo()", "[cipher-base]") {
    const VirgilByteArray emptyContentInfo = VirgilByteArrayUtils::stringToBytes("");
    const VirgilByteArray invalidContentInfo = VirgilByteArrayUtils::stringToBytes("invalid content info");
    const VirgilByteArray validContentInfo = VirgilByteArrayUtils::hexToBytes(
            "308201A7020100308201A006092A864886F70D010703A08201913082018D0201"
                    "023182015E3082015A020102A026042437643464396462392D343833382D3462"
                    "33652D393934622D646464613666633035373630301506072A8648CE3D020106"
                    "0A2B0601040197550105010482011430820110020100305B301506072A8648CE"
                    "3D0201060A2B06010401975501050103420004337F20F3E2B4F85B5E02B22A8A"
                    "EB0A02E58436C00906C85B0A11C8B18F85A96D00000000000000000000000000"
                    "000000000000000000000000000000000000003018060728818C71020502300D"
                    "060960864801650304020205003041300D060960864801650304020205000430F"
                    "B28152BC746813659109EFCCA90B0AE44635E82FCF4BA583267AE5FC8717FC098"
                    "EA0C8E0474E938BDE125401B3911DB3051301D060960864801650304012A04102"
                    "6FA3996462ADA0CC36D3ECC850185D704307E43EE0B2451313BC62FC129F7322A"
                    "44E56632F38EE442E841B1ECBD144609F04CE3FAC5879F719A399DBC6E1B84F3C"
                    "2302606092A864886F70D0107013019060960864801650304012E040C2BC53E10"
                    "6C326CF26CD6C572"
    );
    const VirgilByteArray malformedContentInfo = VirgilByteArrayUtils::hexToBytes(
            "308201A7020100308201A006092A864886F70D010704A08201913082018D0201"
                    "023182015E3082015A020102A026042437643464396462392D343833382D3462"
                    "33652D393934622D646464613666633035373630301506072A8648CE3D020106"
                    "0A2B0601040197550105010482011430820110020100305B301506072A8648CE"
                    "3D0201060A2B06010401975501050103420004337F20F3E2B4F85B5E02B22A8A"
                    "EB0A02E58436C00906C85B0A11C8B18F85A96D00000000000000000000000000"
                    "000000000000000000000000000000000000003018060728818C71020502300D"
                    "060960864801650304020205003041300D060960864801650304020205000430F"
                    "B28152BC746813659109EFCCA90B0AE44635E82FCF4BA583267AE5FC8717FC098"
                    "EA0C8E0474E938BDE125401B3911DB3051301D060960864801650304012A04102"
                    "6FA3996462ADA0CC36D3ECC850185D704307E43EE0B2451313BC62FC129F7322A"
                    "44E56632F38EE442E841B1ECBD144609F04CE3FAC5879F719A399DBC6E1B84F3C"
                    "2302606092A864886F70D0107013019060960864801650304012E040C2BC53E10"
                    "6C326CF26CD6C572"
    );

    VirgilCipherBase cipherBase;
    SECTION("Write valid content info") {
        REQUIRE_NOTHROW(cipherBase.setContentInfo(validContentInfo));
    }

    SECTION("Write empty content info") {
        REQUIRE_THROWS_AS(cipherBase.setContentInfo(emptyContentInfo), VirgilCryptoException);
    }

    SECTION("Write invalid content info") {
        REQUIRE_THROWS_AS(cipherBase.setContentInfo(invalidContentInfo), VirgilCryptoException);
    }

    SECTION("Write unsupported content info") {
        REQUIRE_THROWS_AS(cipherBase.setContentInfo(malformedContentInfo), VirgilCryptoException);
    }
}

TEST_CASE("VirgilCipherBase::computeShared()", "[cipher-base]") {
    VirgilKeyPair bobCurve25519 = VirgilKeyPair::generate(VirgilKeyPair::Type::EC_Curve25519);
    VirgilKeyPair aliceCurve25519 = VirgilKeyPair::generate(VirgilKeyPair::Type::EC_Curve25519);

    VirgilKeyPair bobNist256 = VirgilKeyPair::generate(VirgilKeyPair::Type::EC_SECP256K1);
    VirgilKeyPair aliceNist256 = VirgilKeyPair::generate(VirgilKeyPair::Type::EC_SECP256K1);

    VirgilKeyPair bobBrainpool256 = VirgilKeyPair::generate(VirgilKeyPair::Type::EC_BP256R1);
    VirgilKeyPair aliceBrainpool256 = VirgilKeyPair::generate(VirgilKeyPair::Type::EC_BP256R1);

    VirgilKeyPair bobRsa2048 = VirgilKeyPair::generate(VirgilKeyPair::Type::RSA_2048);
    VirgilKeyPair aliceRsa2048 = VirgilKeyPair::generate(VirgilKeyPair::Type::RSA_2048);


    SECTION("Compute shared key on Elliptic Curve keys of the same group") {
        REQUIRE_NOTHROW(VirgilCipherBase::computeShared(bobCurve25519.publicKey(), aliceCurve25519.privateKey()));
        REQUIRE_NOTHROW(VirgilCipherBase::computeShared(aliceCurve25519.publicKey(), bobCurve25519.privateKey()));

        REQUIRE_NOTHROW(VirgilCipherBase::computeShared(bobNist256.publicKey(), aliceNist256.privateKey()));
        REQUIRE_NOTHROW(VirgilCipherBase::computeShared(aliceNist256.publicKey(), bobNist256.privateKey()));

        REQUIRE_NOTHROW(VirgilCipherBase::computeShared(bobBrainpool256.publicKey(), aliceBrainpool256.privateKey()));
        REQUIRE_NOTHROW(VirgilCipherBase::computeShared(aliceBrainpool256.publicKey(), bobBrainpool256.privateKey()));
    }

    SECTION("Compute shared key on Elliptic Curve keys of the different group") {
        REQUIRE_THROWS_AS(VirgilCipherBase::computeShared(bobCurve25519.publicKey(), aliceNist256.privateKey()),
                VirgilCryptoException);

        REQUIRE_THROWS_AS(VirgilCipherBase::computeShared(bobCurve25519.publicKey(), aliceBrainpool256.privateKey()),
                VirgilCryptoException);

        REQUIRE_THROWS_AS(VirgilCipherBase::computeShared(bobBrainpool256.publicKey(), aliceNist256.privateKey()),
                VirgilCryptoException);
    }

    SECTION("Compute shared key on RSA keys") {
        REQUIRE_THROWS_AS(VirgilCipherBase::computeShared(bobRsa2048.publicKey(), aliceRsa2048.privateKey()),
                VirgilCryptoException);
    }

    SECTION("Compute shared key on RSA key and Elliptic Curve key") {
        REQUIRE_THROWS_AS(VirgilCipherBase::computeShared(bobCurve25519.publicKey(), aliceRsa2048.privateKey()),
                VirgilCryptoException);
    }
}
