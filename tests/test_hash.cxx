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
 * @file test_hash.cxx
 * @brief Covers class VirgilHash
 */

#include "catch.hpp"

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
using virgil::crypto::VirgilByteArray;
using virgil::crypto::str2bytes;
using virgil::crypto::hex2bytes;

#include <virgil/crypto/foundation/VirgilHash.h>
using virgil::crypto::foundation::VirgilHash;

TEST_CASE("MD5", "[hash]") {
    VirgilHash hash = VirgilHash::md5();
    SECTION("Test vector RFC1321 #1") {
        VirgilByteArray testVector = str2bytes("");
        VirgilByteArray testVectorHash = hex2bytes("d41d8cd98f00b204e9800998ecf8427e");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector RFC1321 #2") {
        VirgilByteArray testVector = str2bytes("a");
        VirgilByteArray testVectorHash = hex2bytes("0cc175b9c0f1b6a831c399e269772661");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector RFC1321 #3") {
        VirgilByteArray testVector = str2bytes("abc");
        VirgilByteArray testVectorHash = hex2bytes("900150983cd24fb0d6963f7d28e17f72");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
}

TEST_CASE("SHA-256", "[hash]") {
    VirgilHash hash = VirgilHash::sha256();
    SECTION("Test vector NIST CAVS #1") {
        VirgilByteArray testVector = str2bytes("");
        VirgilByteArray testVectorHash = hex2bytes(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector NIST CAVS #2") {
        VirgilByteArray testVector = hex2bytes("bd");
        VirgilByteArray testVectorHash = hex2bytes(
                "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector NIST CAVS #3") {
        VirgilByteArray testVector = hex2bytes("5fd4");
        VirgilByteArray testVectorHash = hex2bytes(
                "7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
}

TEST_CASE("SHA-384", "[hash]") {
    VirgilHash hash = VirgilHash::sha384();
    SECTION("Test vector NIST CAVS #1") {
        VirgilByteArray testVector = str2bytes("");
        VirgilByteArray testVectorHash = hex2bytes(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                "274edebfe76f65fbd51ad2f14898b95b");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector NIST CAVS #2") {
        VirgilByteArray testVector = hex2bytes("ab");
        VirgilByteArray testVectorHash = hex2bytes(
                "fb94d5be118865f6fcbc978b825da82cff188faec2f66cb84b2537d74b4938469"
                "854b0ca89e66fa2e182834736629f3d");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector NIST CAVS #3") {
        VirgilByteArray testVector = hex2bytes("7c27");
        VirgilByteArray testVectorHash = hex2bytes(
                "3d80be467df86d63abb9ea1d3f9cb39cd19890e7f2c53a6200bedc5006842b35e"
                "820dc4e0ca90ca9b97ab23ef07080fc");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
}

TEST_CASE("SHA-512", "[hash]") {
    VirgilHash hash = VirgilHash::sha512();
    SECTION("Test vector NIST CAVS #1") {
        VirgilByteArray testVector = str2bytes("");
        VirgilByteArray testVectorHash = hex2bytes(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector NIST CAVS #2") {
        VirgilByteArray testVector = hex2bytes("8f");
        VirgilByteArray testVectorHash = hex2bytes(
                "e4cd2d19931b5aad9c920f45f56f6ce34e3d38c6d319a6e11d0588ab8b838576"
                "d6ce6d68eea7c830de66e2bd96458bfa7aafbcbec981d4ed040498c3dd95f22a");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
    SECTION("Test vector NIST CAVS #3") {
        VirgilByteArray testVector = hex2bytes("e724");
        VirgilByteArray testVectorHash = hex2bytes(
                "7dbb520221a70287b23dbcf62bfc1b73136d858e86266732a7fffa875ecaa2c1"
                "b8f673b5c065d360c563a7b9539349f5f59bef8c0c593f9587e3cd50bb26a231");
        REQUIRE(hash.hash(testVector) == testVectorHash);
    }
}

TEST_CASE("HMAC-MD5", "[HMAC hash]") {
    VirgilHash hash = VirgilHash::md5();

    SECTION("Test vector #1") {
        VirgilByteArray key = hex2bytes("61616161616161616161616161616161");
        VirgilByteArray testVector = hex2bytes("b91ce5ac77d33c234e61002ed6");
        VirgilByteArray testVectorHash = hex2bytes("42552882f00bd4633ea81135a184b284");
        REQUIRE(hash.hmac(key, testVector) == testVectorHash);
    }
}
