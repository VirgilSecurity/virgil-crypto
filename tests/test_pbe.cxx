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
 * @file test_pbe.cxx
 * @brief Covers class VirgilPBE
 */

#include "catch.hpp"

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilPBE.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/VirgilCryptoException.h>

using virgil::crypto::str2bytes;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilPBE;
using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::VirgilCryptoException;

TEST_CASE("PBES PKCS#5", "[pbe]") {
    const VirgilByteArray testData = str2bytes("this string will be signed");
    const VirgilByteArray salt = str2bytes("salt");
    const size_t iterationCount = 4096;

    SECTION ("encrypt and decrypt - OK") {
        const VirgilByteArray password = str2bytes("password");
        VirgilPBE pbe = VirgilPBE::pkcs5(salt, iterationCount);
        VirgilByteArray encryptedData = pbe.encrypt(testData, password);
        VirgilByteArray decryptedData = pbe.decrypt(encryptedData, password);
        REQUIRE(decryptedData == testData);
    }

    SECTION ("encrypt and decrypt with very long password - OK") {
        const VirgilByteArray password = VirgilRandom(str2bytes("rng seed")).randomize(2048);
        VirgilPBE pbe = VirgilPBE::pkcs5(salt, iterationCount);
        VirgilByteArray encryptedData = pbe.encrypt(testData, password);
        VirgilByteArray decryptedData = pbe.decrypt(encryptedData, password);
        REQUIRE(decryptedData == testData);
    }
}

TEST_CASE("PBES PKCS#12", "[pbe]") {
    const VirgilByteArray testData = str2bytes("this string will be signed");
    const VirgilByteArray password = str2bytes("password");
    const VirgilByteArray salt = str2bytes("salt");
    const size_t iterationCount = 4096;

    SECTION ("encrypt and decrypt - OK") {
        VirgilPBE pbe = VirgilPBE::pkcs12(salt, iterationCount);
        VirgilByteArray encryptedData = pbe.encrypt(testData, password);
        VirgilByteArray decryptedData = pbe.decrypt(encryptedData, password);
        REQUIRE(decryptedData == testData);
    }

    SECTION ("encrypt and decrypt with very long password - Failed") {
        const VirgilByteArray password = VirgilRandom(str2bytes("rng seed")).randomize(256);
        VirgilPBE pbe = VirgilPBE::pkcs12(salt, iterationCount);
        REQUIRE_THROWS_AS(pbe.encrypt(testData, password), VirgilCryptoException);
    }
}
