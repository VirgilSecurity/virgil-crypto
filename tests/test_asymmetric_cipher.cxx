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
 * @file test_asymmetric_cipher.cxx
 * @brief Covers class VirgilSymmetricCipher
 */

#include "catch.hpp"
#include "deterministic_keys.h"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

using virgil::crypto::str2bytes;
using virgil::crypto::hex2bytes;
using virgil::crypto::bytes2str;
using virgil::crypto::bytes2hex;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::foundation::VirgilAsymmetricCipher;

static const char* const kPublicKey1 =
        "-----BEGIN PUBLIC KEY-----\n"
                "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEWVXg5nZJrFpomSSzuZE8vNs/\n"
                "3PsrQZaTKuBw6dPdyg8NZMUDTjahxm54P14vOW6Cw6PtrX0a53TZqQTC0gEQRpZP\n"
                "x378rZVmMnkswY+nLcYrXfBGdmHsEbgleiDMiSFiJMqpL+OKTMeqPsnBM6CaBIyF\n"
                "XPM6wmFdMPlOngzWBvM=\n"
                "-----END PUBLIC KEY-----\n";

static const char* const kPrivateKey1 =
        "-----BEGIN EC PRIVATE KEY-----\n"
                "MIHbAgEBBEEAnhfPmR0k5L45J5m2WaEjQcZ5rmbJPLcrth3X59oL2bJ9PZs+ZZ7F\n"
                "C0mScOlnzvseb4rg2P2k3o93d+fNCcu84KALBgkrJAMDAggBAQ2hgYUDgYIABFlV\n"
                "4OZ2SaxaaJkks7mRPLzbP9z7K0GWkyrgcOnT3coPDWTFA042ocZueD9eLzlugsOj\n"
                "7a19Gud02akEwtIBEEaWT8d+/K2VZjJ5LMGPpy3GK13wRnZh7BG4JXogzIkhYiTK\n"
                "qS/jikzHqj7JwTOgmgSMhVzzOsJhXTD5Tp4M1gbz\n"
                "-----END EC PRIVATE KEY-----\n";

static const char* const kPrivateKey1DER =
        "3081DB0201010441009E17CF991D24E4"
                "BE392799B659A12341C679AE66C93CB7"
                "2BB61DD7E7DA0BD9B27D3D9B3E659EC5"
                "0B499270E967CEFB1E6F8AE0D8FDA4DE"
                "8F7777E7CD09CBBCE0A00B06092B2403"
                "03020801010DA1818503818200045955"
                "E0E67649AC5A689924B3B9913CBCDB3F"
                "DCFB2B4196932AE070E9D3DDCA0F0D64"
                "C5034E36A1C66E783F5E2F396E82C3A3"
                "EDAD7D1AE774D9A904C2D2011046964F"
                "C77EFCAD956632792CC18FA72DC62B5D"
                "F0467661EC11B8257A20CC89216224CA"
                "A92FE38A4CC7AA3EC9C133A09A048C85"
                "5CF33AC2615D30F94E9E0CD606F3";

static const char* const kMalformedPrivateKey1 =
        "-----BEGIN EC PRIVATE KEY-----\n"
                "MIHbAgEBBEEAnhfPmR0k5L45J5m2WaEjQcZ5rmbJPLcrth3X59oL2bJ9PZs+ZZ7F\n"
                "C0mScOlnzvseb4rg2P2k3o93d+fNacu84KALBgkrJAMDAggBAQ2hgYUDgYIABFlV\n"
                "4OZ2SaxaaJkks7mRPLzbP9z7K0GskyrgcOnT3coPDWTFA042ocZueD9eLzlugsOj\n"
                "7a19Gud02akEwtIBEEaWT8d+/K2VZjJ5LMGPpy3GK13wRnZh7BG4JXogzIkhYiTK\n"
                "qS/jikzHqj7JwTOgmgSMhVzzOsJhXTD5Tp4M1gbz\n"
                "-----END EC PRIVATE KEY-----\n";

static const char* const kPublicKey2 =
        "-----BEGIN PUBLIC KEY-----\n"
                "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEICO4EYlqUNc7YvjI4WkebcQ4\n"
                "XS+BhIxs0wbcdjqy4T+K9UDDnUiLHfDh9HasbrllUeHaoYOawuI8aIa/84+mjAOo\n"
                "n67rIbrrgFps/3vJ8lVkWA8k70XZDus7QUpfSjYnRQsT55aJn4VUM2f98unO3Zzv\n"
                "vxDdHHuheBFgLgho3zo=\n"
                "-----END PUBLIC KEY-----\n";

static const char* const kPrivateKey2 =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                "MIIBKTA0BgoqhkiG9w0BDAEDMCYEIJ2CZ9XD79se4sWO8zaB8ooKkf1IR/cymmox\n"
                "NH0pe2zCAgIgAASB8HPqZNMejdzjsPeLJrLj1SXdES8FOUgWDbIhFLm/6G3leCNi\n"
                "/7scgIOwook/f5qEL3ydHobXcYrr5Ltlr5o5BsSBELBAJKoUKcWmu8Aub03v/wIe\n"
                "TNsVhxA/4mn5kgs6BwJp59oODv0YqpRAFsMQsXJaXjePVWpKLsDAooT8Wa0s5cfP\n"
                "tURNzUUQG7COakN4PF01MXgHYEsvc/ygXI/QUHIBPwBVV7bx3lIV1xDy5WCNgBfd\n"
                "EEd8luTaIzd15Y7ahooAA9K1WDPEhtq0gl8jG5vSbZ+BCaMNd43+Gksno4c9oBkZ\n"
                "sMaFiu8OBbyVfjhr9g==\n"
                "-----END ENCRYPTED PRIVATE KEY-----\n";

static const char* const kPrivateKey2DER =
        "308201293034060A2A864886F70D010C"
                "0103302604209D8267D5C3EFDB1EE2C5"
                "8EF33681F28A0A91FD4847F7329A6A31"
                "347D297B6CC2020220000481F073EA64"
                "D31E8DDCE3B0F78B26B2E3D525DD112F"
                "053948160DB22114B9BFE86DE5782362"
                "FFBB1C8083B0A2893F7F9A842F7C9D1E"
                "86D7718AEBE4BB65AF9A3906C48110B0"
                "4024AA1429C5A6BBC02E6F4DEFFF021E"
                "4CDB1587103FE269F9920B3A070269E7"
                "DA0E0EFD18AA944016C310B1725A5E37"
                "8F556A4A2EC0C0A284FC59AD2CE5C7CF"
                "B5444DCD45101BB08E6A43783C5D3531"
                "7807604B2F73FCA05C8FD05072013F00"
                "5557B6F1DE5215D710F2E5608D8017DD"
                "10477C96E4DA233775E58EDA868A0003"
                "D2B55833C486DAB4825F231B9BD26D9F"
                "8109A30D778DFE1A4B27A3873DA01919"
                "B0C6858AEF0E05BC957E386BF6";

static const char* const kMalformedPrivateKey2 =
        "-----BEGIN ENC PRIVATE KEY-----\n"
                "MIIBKTA0BgoqhkiG9w0BDAEDMCYEIJ2CZ9XD79se4sWO8zaB8ooKkf1IR/cymmox\n"
                "NH0pe2zCAgIgAASB8HPqZNMejdzjsseLJrLj1SXdES8FOUgWDbIhFLm/6G3leCNi\n"
                "/7scgIOwook/f5qEL3ydHobXcYrr5Ltlr5o5BsSBELBAJKoUKcWmu8Aub03v/wIe\n"
                "TNsVhxA/4mn5kgs6BwJp59oODv0YqpRAFsMQsXJaXjePVWpKLsDAooT8Wa0s5cfP\n"
                "tURNzUUQG7COakN4PF01MXgHYEsvc/ygXI/QsHIBPwBVV7bx3lIV1xDy5WCNgBfd\n"
                "EEd8luTaIzd15Y7ahooAA9K1WDPEhtq0gl8jG5vSbZ+BCaMNd43+Gksno4c9oBkZ\n"
                "sMaFiu8OBbyVfjhr9g==\n"
                "-----END ENC PRIVATE KEY-----\n";

static const char* const kPwdPrivateKey2 = "strong_pwd";
static const char* const kWrongPwdPrivateKey2 = "wrong_strong_pwd";

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
    SECTION("check if private key is encrypted (PEM)") {
        REQUIRE(VirgilAsymmetricCipher::isPrivateKeyEncrypted(str2bytes(kPrivateKey2)));
        REQUIRE_FALSE(VirgilAsymmetricCipher::isPrivateKeyEncrypted(str2bytes(kPrivateKey1)));
    }
    SECTION("check if private key is encrypted (DER)") {
        REQUIRE(VirgilAsymmetricCipher::isPrivateKeyEncrypted(hex2bytes(kPrivateKey2DER)));
        REQUIRE_FALSE(VirgilAsymmetricCipher::isPrivateKeyEncrypted(hex2bytes(kPrivateKey1DER)));
    }
    SECTION("check malformed private key throws") {
        REQUIRE_THROWS(VirgilAsymmetricCipher::checkPrivateKeyPassword(str2bytes(kMalformedPrivateKey2),
                str2bytes(kPwdPrivateKey2)));
        REQUIRE_THROWS(VirgilAsymmetricCipher::isPrivateKeyEncrypted(str2bytes(kMalformedPrivateKey1)));
        REQUIRE_THROWS(VirgilAsymmetricCipher::isPrivateKeyEncrypted(str2bytes(kMalformedPrivateKey2)));
    }
}

TEST_CASE("Asymmetric Cipher - Deterministic Key Pair generation", "[asymmetric-cipher]") {
    VirgilAsymmetricCipher cipher;
    VirgilByteArray strongKeyMaterial = hex2bytes(kDeterministic_KeyMaterial);
    VirgilByteArray weakKeyMaterial = VirgilByteArray(31, 0xAB);
    VirgilByteArray strongEnaughKeyMaterial = VirgilByteArray(32, 0xAB);

    SECTION("key material with length 31 fail") {
        REQUIRE_THROWS(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::RSA_256, weakKeyMaterial));
    }

    SECTION("key material with length 32 pass") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::RSA_256, strongEnaughKeyMaterial));
    }

    SECTION("check RSA_256") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::RSA_256, strongKeyMaterial));
        REQUIRE(kDeterministic_RSA_256_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_RSA_256_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }

    SECTION("check RSA_8192") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::RSA_8192, strongKeyMaterial));
        REQUIRE(kDeterministic_RSA_8192_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_RSA_8192_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }

    SECTION("check EC_SECP192R1") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::EC_SECP192R1, strongKeyMaterial));
        REQUIRE(kDeterministic_EC_SECP192R1_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_EC_SECP192R1_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }

    SECTION("check EC_SECP521R1") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::EC_SECP521R1, strongKeyMaterial));
        REQUIRE(kDeterministic_EC_SECP521R1_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_EC_SECP521R1_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }

    SECTION("check EC_BP512R1") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::RSA_256, strongKeyMaterial));
        REQUIRE(kDeterministic_RSA_256_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_RSA_256_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }

    SECTION("check EC_SECP256K1") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::EC_SECP256K1, strongKeyMaterial));
        REQUIRE(kDeterministic_EC_SECP256K1_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_EC_SECP256K1_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }

    SECTION("check FAST_EC_X25519") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::FAST_EC_X25519, strongKeyMaterial));
        REQUIRE(kDeterministic_FAST_EC_X25519_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_FAST_EC_X25519_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }

    SECTION("check FAST_EC_ED25519") {
        REQUIRE_NOTHROW(cipher.genKeyPairFromKeyMaterial(VirgilKeyPair::Algorithm::FAST_EC_ED25519, strongKeyMaterial));
        REQUIRE(kDeterministic_FAST_EC_ED25519_Public == bytes2str(cipher.exportPublicKeyToPEM()));
        REQUIRE(kDeterministic_FAST_EC_ED25519_Private == bytes2str(cipher.exportPrivateKeyToPEM()));
    }
}
