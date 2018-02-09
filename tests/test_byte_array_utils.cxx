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
 * @file test_hash.cxx
 * @brief Covers class VirgilByteArrayUtils
 */

#include "catch.hpp"

#include <iostream>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;

TEST_CASE("Json -> bytes", "[byte-array]") {
    std::string pretty_json =
            "{"
                    "    \"object\" : {"
                    "        \"number_integer\" : 123,"
                    "        \"bool_true\" : true,"
                    "        \"bool_false\" : false,"
                    "        \"string\" : \"test string\""
                    "    },"
                    "    \"array\" : ["
                    "        1, true, false, \"test string\""
                    "    ],"
                    "    \"bool_true\" : true,"
                    "    \"null\" : null,"
                    "    \"bool_false\" : false,"
                    "    \"number_integer\" : 123,"
                    "    \"string\" : \"test_string\""
                    "}";
    std::string minified_json =
            "{\"object\":{\"number_integer\":123,\"bool_true\":true,\"bool_false\":false,\""
                    "string\":\"test string\"},\"array\":[1,true,false,\"test string\"],\"bool_true"
                    "\":true,\"bool_false\":false,\"number_integer\":123,\"string\":\"test_string\","
                    "\"null\" : null}";
    std::string rearranged_json =
            "{"
                    "    \"bool_false\" : false,"
                    "    \"null\" : null,"
                    "    \"number_integer\" : 123,"
                    "    \"array\" : ["
                    "        1, true, false, \"test string\""
                    "    ],"
                    "    \"string\" : \"test_string\","
                    "    \"bool_true\" : true,"
                    "    \"object\" : {"
                    "        \"bool_false\" : false,"
                    "        \"string\" : \"test string\","
                    "        \"bool_true\" : true,"
                    "        \"number_integer\" : 123"
                    "    }"
                    "}";

    SECTION("Test JSON to bytes convertion") {
        VirgilByteArray pretty_json_bytes = VirgilByteArrayUtils::jsonToBytes(pretty_json);
        VirgilByteArray minified_json_bytes = VirgilByteArrayUtils::jsonToBytes(minified_json);
        VirgilByteArray rearranged_json_bytes = VirgilByteArrayUtils::jsonToBytes(rearranged_json);
        REQUIRE(VirgilByteArrayUtils::bytesToHex(pretty_json_bytes) ==
                VirgilByteArrayUtils::bytesToHex(minified_json_bytes));
        REQUIRE(VirgilByteArrayUtils::bytesToHex(pretty_json_bytes) ==
                VirgilByteArrayUtils::bytesToHex(rearranged_json_bytes));
    }
}
