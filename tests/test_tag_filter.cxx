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
 * @file test_tag_filter.cxx
 * @brief Covers class VirgilTagFilter
 */


#ifndef VIRGIL_CRYPTO_CONFIG_FILE
#include <virgil/crypto/config.h>
#else
#include VIRGIL_CRYPTO_CONFIG_FILE
#endif

#if defined(VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE)

#include "catch.hpp"

#include <iostream>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/internal/VirgilTagFilter.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::foundation::internal::VirgilTagFilter;

TEST_CASE("Get TAG", "[tag-filter]") {
    VirgilTagFilter tagFilter;
    size_t kTagLen = 16;

    SECTION("Case 1") {
        tagFilter.reset(kTagLen);
        tagFilter.process(VirgilByteArrayUtils::hexToBytes(
                "5eb9ee8ee83801858815e0fc301204102ccda65f87808b4dcdfebd970b881e95")
        );
        REQUIRE(kTagLen == tagFilter.tag().size());
        REQUIRE(VirgilByteArrayUtils::bytesToHex(tagFilter.tag()) == "2ccda65f87808b4dcdfebd970b881e95");
    }
    SECTION("Case 2") {
        tagFilter.reset(kTagLen);
        tagFilter.process(VirgilByteArrayUtils::hexToBytes(
                "11111111111111301204102ccda65f87808b4dcdfebd970b881e95")
        );
        REQUIRE(kTagLen == tagFilter.tag().size());
        REQUIRE(VirgilByteArrayUtils::bytesToHex(tagFilter.tag()) == "2ccda65f87808b4dcdfebd970b881e95");
    }
}

#endif //VIRGIL_CRYPTO_FOUNDATION_SYMMETRIC_CIPHER_MODULE
