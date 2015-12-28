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
 * @file test_ssymmetric_cipher.cxx
 * @brief Covers class VirgilSymmetricCipher
 */

#include "catch.hpp"

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

using virgil::crypto::str2bytes;
using virgil::crypto::hex2bytes;
using virgil::crypto::bytes2str;
using virgil::crypto::bytes2hex;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilAsymmetricCipher;

static const char * const kPublicKey1 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEWVXg5nZJrFpomSSzuZE8vNs/\n"
    "3PsrQZaTKuBw6dPdyg8NZMUDTjahxm54P14vOW6Cw6PtrX0a53TZqQTC0gEQRpZP\n"
    "x378rZVmMnkswY+nLcYrXfBGdmHsEbgleiDMiSFiJMqpL+OKTMeqPsnBM6CaBIyF\n"
    "XPM6wmFdMPlOngzWBvM=\n"
    "-----END PUBLIC KEY-----\n";

static const char * const kPrivateKey1 =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MIHbAgEBBEEAnhfPmR0k5L45J5m2WaEjQcZ5rmbJPLcrth3X59oL2bJ9PZs+ZZ7F\n"
    "C0mScOlnzvseb4rg2P2k3o93d+fNCcu84KALBgkrJAMDAggBAQ2hgYUDgYIABFlV\n"
    "4OZ2SaxaaJkks7mRPLzbP9z7K0GWkyrgcOnT3coPDWTFA042ocZueD9eLzlugsOj\n"
    "7a19Gud02akEwtIBEEaWT8d+/K2VZjJ5LMGPpy3GK13wRnZh7BG4JXogzIkhYiTK\n"
    "qS/jikzHqj7JwTOgmgSMhVzzOsJhXTD5Tp4M1gbz\n"
    "-----END EC PRIVATE KEY-----\n";

static const char * const kPublicKey2 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEICO4EYlqUNc7YvjI4WkebcQ4\n"
    "XS+BhIxs0wbcdjqy4T+K9UDDnUiLHfDh9HasbrllUeHaoYOawuI8aIa/84+mjAOo\n"
    "n67rIbrrgFps/3vJ8lVkWA8k70XZDus7QUpfSjYnRQsT55aJn4VUM2f98unO3Zzv\n"
    "vxDdHHuheBFgLgho3zo=\n"
    "-----END PUBLIC KEY-----\n";

static const char * const kPrivateKey2 =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIBKTA0BgoqhkiG9w0BDAEDMCYEIJ2CZ9XD79se4sWO8zaB8ooKkf1IR/cymmox\n"
    "NH0pe2zCAgIgAASB8HPqZNMejdzjsPeLJrLj1SXdES8FOUgWDbIhFLm/6G3leCNi\n"
    "/7scgIOwook/f5qEL3ydHobXcYrr5Ltlr5o5BsSBELBAJKoUKcWmu8Aub03v/wIe\n"
    "TNsVhxA/4mn5kgs6BwJp59oODv0YqpRAFsMQsXJaXjePVWpKLsDAooT8Wa0s5cfP\n"
    "tURNzUUQG7COakN4PF01MXgHYEsvc/ygXI/QUHIBPwBVV7bx3lIV1xDy5WCNgBfd\n"
    "EEd8luTaIzd15Y7ahooAA9K1WDPEhtq0gl8jG5vSbZ+BCaMNd43+Gksno4c9oBkZ\n"
    "sMaFiu8OBbyVfjhr9g==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";

static const char * const kPwdPrivateKey2 = "strong_pwd";
static const char * const kWrongPwdPrivateKey2 = "wrong_strong_pwd";

TEST_CASE("Asymmetric Cipher - Keys Validation", "[asymmetric-cipher]") {
    SECTION("check key pair match") {
        REQUIRE(VirgilAsymmetricCipher::isKeyPairMatch(
                str2bytes(kPublicKey1), str2bytes(kPrivateKey1)));
        REQUIRE(VirgilAsymmetricCipher::isKeyPairMatch(
                str2bytes(kPublicKey2), str2bytes(kPrivateKey2), str2bytes(kPwdPrivateKey2)));
        REQUIRE_FALSE(VirgilAsymmetricCipher::isKeyPairMatch(
                str2bytes(kPublicKey2), str2bytes(kPrivateKey1)));
        REQUIRE_FALSE(VirgilAsymmetricCipher::isKeyPairMatch(
                str2bytes(kPublicKey1), str2bytes(kPrivateKey2), str2bytes(kPwdPrivateKey2)));
    }
    SECTION("check private key password") {
        REQUIRE(VirgilAsymmetricCipher::checkPrivateKeyPassword(
            str2bytes(kPrivateKey2), str2bytes(kPwdPrivateKey2)));
        REQUIRE_FALSE(VirgilAsymmetricCipher::checkPrivateKeyPassword(
            str2bytes(kPrivateKey2), str2bytes(kWrongPwdPrivateKey2)));
    }
    SECTION("check if private key is encrypted") {
        REQUIRE(VirgilAsymmetricCipher::isPrivateKeyEncrypted(str2bytes(kPrivateKey2)));
        REQUIRE_FALSE(VirgilAsymmetricCipher::isPrivateKeyEncrypted(str2bytes(kPrivateKey1)));
    }
}
