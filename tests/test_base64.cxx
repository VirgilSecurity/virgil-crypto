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
 * @file test_base64.cxx
 * @brief Covers class VirgilBase64
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::foundation::VirgilBase64;

TEST_CASE("VirgilBase64 - Success", "[base64]") {
    SECTION("Test case 1") {
        const VirgilByteArray plain_data = VirgilByteArrayUtils::stringToBytes("");
        const std::string base64_data = "";

        REQUIRE(VirgilBase64::encode(plain_data) == base64_data);
        REQUIRE(VirgilBase64::decode(base64_data) == plain_data);
    }
    SECTION("Test case 2") {
        const VirgilByteArray plain_data = VirgilByteArrayUtils::stringToBytes("f");
        const std::string base64_data = "Zg==";

        REQUIRE(VirgilBase64::encode(plain_data) == base64_data);
        REQUIRE(VirgilBase64::decode(base64_data) == plain_data);
    }
    SECTION("Test case 3") {
        const VirgilByteArray plain_data = VirgilByteArrayUtils::stringToBytes("fo");
        const std::string base64_data = "Zm8=";

        REQUIRE(VirgilBase64::encode(plain_data) == base64_data);
        REQUIRE(VirgilBase64::decode(base64_data) == plain_data);
    }
    SECTION("Test case 4") {
        const VirgilByteArray plain_data = VirgilByteArrayUtils::stringToBytes("foo");
        const std::string base64_data = "Zm9v";

        REQUIRE(VirgilBase64::encode(plain_data) == base64_data);
        REQUIRE(VirgilBase64::decode(base64_data) == plain_data);
    }
    SECTION("Test case 5") {
        const VirgilByteArray plain_data = VirgilByteArrayUtils::stringToBytes("foob");
        const std::string base64_data = "Zm9vYg==";

        REQUIRE(VirgilBase64::encode(plain_data) == base64_data);
        REQUIRE(VirgilBase64::decode(base64_data) == plain_data);
    }
    SECTION("Test case 6") {
        const VirgilByteArray plain_data = VirgilByteArrayUtils::stringToBytes("fooba");
        const std::string base64_data = "Zm9vYmE=";

        REQUIRE(VirgilBase64::encode(plain_data) == base64_data);
        REQUIRE(VirgilBase64::decode(base64_data) == plain_data);
    }
    SECTION("Test case 7") {
        const VirgilByteArray plain_data = VirgilByteArrayUtils::stringToBytes("foobar");
        const std::string base64_data = "Zm9vYmFy";

        REQUIRE(VirgilBase64::encode(plain_data) == base64_data);
        REQUIRE(VirgilBase64::decode(base64_data) == plain_data);
    }
}
