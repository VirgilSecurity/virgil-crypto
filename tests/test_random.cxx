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
 * @file test_random.cxx
 * @brief Covers class VirgilRandom
 */

#include "catch.hpp"


#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/VirgilRandom.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::foundation::VirgilRandom;

TEST_CASE("Randomize sequence", "[random]") {
    VirgilRandom random("secure seed");

    SECTION("Success") {
        constexpr size_t kSequenceLength = 1024;
        VirgilByteArray data;
        REQUIRE_NOTHROW(data = random.randomize(kSequenceLength));
        REQUIRE(data.size() == kSequenceLength);
    }

    SECTION("Too BIG") {
        constexpr size_t kSequenceLength = std::numeric_limits<size_t>::max();
        REQUIRE_THROWS_AS(random.randomize(kSequenceLength).size(), std::bad_alloc);
    }
}

TEST_CASE("Randomize number", "[random]") {
    VirgilRandom random("secure seed");

    SECTION("Success") {
        REQUIRE_NOTHROW(random.randomize());
    }
}

TEST_CASE("Randomize number in range", "[random]") {
    VirgilRandom random("secure seed");

    constexpr size_t kMinValue = 10;
    constexpr size_t kMaxValue = 100;

    SECTION("Success") {
        size_t value = 0;
        REQUIRE_NOTHROW(value = random.randomize(kMinValue, kMaxValue));
        REQUIRE(value >= kMinValue);
        REQUIRE(value <= kMaxValue);
    }

    SECTION("Wrong range") {
        REQUIRE_THROWS_AS(random.randomize(kMaxValue, kMinValue), VirgilCryptoException);
    }
}