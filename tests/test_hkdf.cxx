/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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
 * @file test_hkdf.cxx
 * @brief Covers class VirgilHKDF
 */

#include "catch.hpp"

#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilHKDF.h>

#include <array>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::VirgilHKDF;

using virgil::crypto::hex2bytes;
using virgil::crypto::bytes2hex;

struct TestVector {
    const char* testVectorId;
    VirgilHash::Algorithm hashAlgorithm;
    VirgilByteArray keyMaterial;
    VirgilByteArray salt;
    VirgilByteArray info;
    size_t outSize;
    VirgilByteArray derivedData;
};

static constexpr auto TestVectorCount = 6;
static const std::array<TestVector, TestVectorCount>& getTestVectors();


SCENARIO("Check HKDF test vectors", "[kdf][hkdf]") {
    for (const auto& testVector : getTestVectors()) {
        auto kdf = VirgilHKDF(testVector.hashAlgorithm);
        GIVEN(testVector.testVectorId) {
            auto derivedData = kdf.derive(
                testVector.keyMaterial,
                testVector.salt,
                testVector.info,
                testVector.outSize
            );
            REQUIRE(bytes2hex(derivedData) == bytes2hex(testVector.derivedData));
        }
    }
}

static const std::array<TestVector, TestVectorCount>& getTestVectors() {
    static const std::array<TestVector, TestVectorCount> testVectors{
        {
            {
                .testVectorId = "RFC 5869 test vector 1. Basic test case with SHA-256.",
                .hashAlgorithm = VirgilHash::Algorithm::SHA256,
                .keyMaterial = hex2bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                .salt = hex2bytes("000102030405060708090a0b0c"),
                .info = hex2bytes("f0f1f2f3f4f5f6f7f8f9"),
                .outSize = 42,
                .derivedData = hex2bytes("3cb25f25faacd57a90434f64d0362f2a"
                                             "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                             "34007208d5b887185865")
            },
            {
                .testVectorId = "RFC 5869 test vector 2. Test with SHA-256 and longer inputs/outputs.",
                .hashAlgorithm = VirgilHash::Algorithm::SHA256,
                .keyMaterial = hex2bytes("000102030405060708090a0b0c0d0e0f"
                                             "101112131415161718191a1b1c1d1e1f"
                                             "202122232425262728292a2b2c2d2e2f"
                                             "303132333435363738393a3b3c3d3e3f"
                                             "404142434445464748494a4b4c4d4e4f"),
                .salt = hex2bytes("606162636465666768696a6b6c6d6e6f"
                                      "707172737475767778797a7b7c7d7e7f"
                                      "808182838485868788898a8b8c8d8e8f"
                                      "909192939495969798999a9b9c9d9e9f"
                                      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                .info = hex2bytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                                      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                                      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                .outSize = 82,
                .derivedData = hex2bytes("b11e398dc80327a1c8e7f78c596a4934"
                                             "4f012eda2d4efad8a050cc4c19afa97c"
                                             "59045a99cac7827271cb41c65e590e09"
                                             "da3275600c2f09b8367793a9aca3db71"
                                             "cc30c58179ec3e87c14c01d5c1f3434f"
                                             "1d87")
            },
            {
                .testVectorId = "RFC 5869 test vector 3. Test with SHA-256 and zero-length salt/info.",
                .hashAlgorithm = VirgilHash::Algorithm::SHA256,
                .keyMaterial = hex2bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                .salt = hex2bytes(""),
                .info = hex2bytes(""),
                .outSize = 42,
                .derivedData = hex2bytes("8da4e775a563c18f715f802a063c5a31"
                                             "b8a11f5c5ee1879ec3454e5f3c738d2d"
                                             "9d201395faa4b61a96c8")
            },
            {
                .testVectorId = "RFC 5869 test vector 4. Basic test case with SHA-1.",
                .hashAlgorithm = VirgilHash::Algorithm::SHA1,
                .keyMaterial = hex2bytes("0b0b0b0b0b0b0b0b0b0b0b"),
                .salt = hex2bytes("000102030405060708090a0b0c"),
                .info = hex2bytes("f0f1f2f3f4f5f6f7f8f9"),
                .outSize = 42,
                .derivedData = hex2bytes("085a01ea1b10f36933068b56efa5ad81"
                                             "a4f14b822f5b091568a9cdd4f155fda2"
                                             "c22e422478d305f3f896")
            },
            {
                .testVectorId = "RFC 5869 test vector 5. Test with SHA-1 and longer inputs/outputs.",
                .hashAlgorithm = VirgilHash::Algorithm::SHA1,
                .keyMaterial = hex2bytes("000102030405060708090a0b0c0d0e0f"
                                             "101112131415161718191a1b1c1d1e1f"
                                             "202122232425262728292a2b2c2d2e2f"
                                             "303132333435363738393a3b3c3d3e3f"
                                             "404142434445464748494a4b4c4d4e4f"),
                .salt = hex2bytes("606162636465666768696a6b6c6d6e6f"
                                      "707172737475767778797a7b7c7d7e7f"
                                      "808182838485868788898a8b8c8d8e8f"
                                      "909192939495969798999a9b9c9d9e9f"
                                      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                .info = hex2bytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                                      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                                      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                .outSize = 82,
                .derivedData = hex2bytes("0bd770a74d1160f7c9f12cd5912a06eb"
                                             "ff6adcae899d92191fe4305673ba2ffe"
                                             "8fa3f1a4e5ad79f3f334b3b202b2173c"
                                             "486ea37ce3d397ed034c7f9dfeb15c5e"
                                             "927336d0441f4c4300e2cff0d0900b52"
                                             "d3b4")
            },
            {
                .testVectorId = "RFC 5869 test vector 6. Test with SHA-1 and zero-length salt/info.",
                .hashAlgorithm = VirgilHash::Algorithm::SHA1,
                .keyMaterial = hex2bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                .salt = hex2bytes(""),
                .info = hex2bytes(""),
                .outSize = 42,
                .derivedData = hex2bytes("0ac1af7002b3d761d1e55298da9d0506"
                                             "b9ae52057220a306e07b6b87e8df21d0"
                                             "ea00033de03984d34918")
            }
        }
    };
    return testVectors;
}
