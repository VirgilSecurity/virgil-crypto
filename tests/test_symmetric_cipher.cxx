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
 * @file test_symmetric_cipher.cxx
 * @brief Covers class VirgilSymmetricCipher
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilRandom.h>

using virgil::crypto::str2bytes;
using virgil::crypto::hex2bytes;
using virgil::crypto::bytes2str;
using virgil::crypto::bytes2hex;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilSymmetricCipher;
using virgil::crypto::foundation::VirgilRandom;

static void test_symmetric_cipher(VirgilSymmetricCipher::Algorithm algorithm) {
    VirgilByteArray plainData = str2bytes("data to be encrypted with symmetric cipher");

    VirgilSymmetricCipher cipher(algorithm);

    SECTION("with known KEY and IV") {
        // Init keys
        VirgilByteArray key = hex2bytes("194122b1bee2f8c25ea5e0f02b1a3376d3a3dd1252365a2acefabead3cf6ab4c");
        VirgilByteArray iv = hex2bytes("fb0a9fc004041e7d95b7555d282f0bd653d6d688fd6f5be26863115a7c1254e0");
        key.resize(cipher.keyLength());
        iv.resize(cipher.ivSize());
        // Encrypt
        cipher.setEncryptionKey(key);
        if (cipher.isSupportPadding()) {
            cipher.setPadding(VirgilSymmetricCipher::Padding::PKCS7);
        }
        VirgilByteArray encryptedData = cipher.crypt(plainData, iv);
        // Decrypt
        cipher.clear();
        cipher.setDecryptionKey(key);
        if (cipher.isSupportPadding()) {
            cipher.setPadding(VirgilSymmetricCipher::Padding::PKCS7);
        }
        VirgilByteArray decryptedData = cipher.crypt(encryptedData, iv);
        // Check
        REQUIRE(bytes2str(plainData) == bytes2str(decryptedData));
    }

    SECTION("with random KEY and IV") {
        // Init randomizer
        VirgilRandom random(str2bytes("test_symmetric_cipher"));
        // Init keys
        VirgilByteArray key = random.randomize(cipher.keyLength());
        VirgilByteArray iv = random.randomize(cipher.ivSize());
        // Encrypt
        cipher.setEncryptionKey(key);
        if (cipher.isSupportPadding()) {
            cipher.setPadding(VirgilSymmetricCipher::Padding::PKCS7);
        }
        VirgilByteArray encryptedData = cipher.crypt(plainData, iv);
        // Decrypt
        cipher.clear();
        cipher.setDecryptionKey(key);
        if (cipher.isSupportPadding()) {
            cipher.setPadding(VirgilSymmetricCipher::Padding::PKCS7);
        }
        VirgilByteArray decryptedData = cipher.crypt(encryptedData, iv);
        // Check
        REQUIRE(bytes2str(plainData) == bytes2str(decryptedData));
    }
}

TEST_CASE("Symmetric Cipher", "[symmetric-cipher]") {

    SECTION("AES-128-CBC") {
        test_symmetric_cipher(VirgilSymmetricCipher::Algorithm::AES_128_CBC);
    }
    SECTION("AES-256-CBC") {
        test_symmetric_cipher(VirgilSymmetricCipher::Algorithm::AES_256_CBC);
    }
    SECTION("AES-128-GCM") {
        test_symmetric_cipher(VirgilSymmetricCipher::Algorithm::AES_128_GCM);
    }
    SECTION("AES-256-GCM") {
        test_symmetric_cipher(VirgilSymmetricCipher::Algorithm::AES_256_GCM);
    }

}
