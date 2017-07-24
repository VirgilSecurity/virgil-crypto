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
 * @file test_copy_move_contract.cxx
 * @brief Covers class contracts: copyable, moveable
 */

#include "catch.hpp"

#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilKDF.h>
#include <virgil/crypto/foundation/VirgilPBE.h>
#include <virgil/crypto/foundation/VirgilPBKDF.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>

#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/foundation/cms/VirgilCMSKeyTransRecipient.h>
#include <virgil/crypto/foundation/cms/VirgilCMSPasswordRecipient.h>
#include <virgil/crypto/foundation/cms/VirgilCMSContent.h>
#include <virgil/crypto/foundation/cms/VirgilCMSContentInfo.h>
#include <virgil/crypto/foundation/cms/VirgilCMSEncryptedContent.h>
#include <virgil/crypto/foundation/cms/VirgilCMSEnvelopedData.h>

#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/VirgilCustomParams.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/VirgilChunkCipher.h>
#include <virgil/crypto/VirgilTinyCipher.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/VirgilStreamSigner.h>


#define SECTION_CONTRACT_MOVE_ONLY(type) \
    SECTION(#type) { \
        REQUIRE_FALSE(std::is_copy_constructible<type>::value); \
        REQUIRE_FALSE(std::is_copy_assignable<type>::value); \
        REQUIRE(std::is_move_constructible<type>::value); \
        REQUIRE(std::is_move_assignable<type>::value); \
        REQUIRE(std::is_nothrow_move_constructible<type>::value); \
        REQUIRE(std::is_nothrow_move_assignable<type>::value); \
    }

#define SECTION_CONTRACT_COPY_AND_MOVE(type) \
    SECTION(#type) { \
        REQUIRE(std::is_copy_constructible<type>::value); \
        REQUIRE(std::is_copy_assignable<type>::value); \
        REQUIRE(std::is_move_constructible<type>::value); \
        REQUIRE(std::is_move_assignable<type>::value); \
        REQUIRE(std::is_nothrow_move_constructible<type>::value); \
        REQUIRE(std::is_nothrow_move_assignable<type>::value); \
    }

TEST_CASE("Check contract: move only", "[copy/move]") {
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::foundation::asn1::VirgilAsn1Reader);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::foundation::asn1::VirgilAsn1Writer);

    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::foundation::VirgilKDF);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::foundation::VirgilPBE);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::foundation::VirgilPBKDF);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::foundation::VirgilAsymmetricCipher);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::foundation::VirgilSymmetricCipher);

    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::VirgilCipher);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::VirgilStreamCipher);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::VirgilChunkCipher);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::VirgilTinyCipher);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::VirgilSigner);
    SECTION_CONTRACT_MOVE_ONLY(virgil::crypto::VirgilStreamSigner);
}

TEST_CASE("Check contract: copy and move", "[copy/move]") {
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::VirgilHash);
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::VirgilRandom);

    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::cms::VirgilCMSContent);
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent);
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData);
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient);
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient);

#if defined(__GNUG__) && (__GNUC__ == 5 && __GNUC_MINOR__ >= 5 )
    // VirgilCryptoException contains field with type std::string,
    // GCC has bug: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=58265, and it will be fixed in the version 5.5,
    // it means next condition can not by satisfied:
    //      static_assert(std::is_nothrow_move_assignable<VirgilCryptoException>::value, "Fail");
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::VirgilCryptoException);
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::foundation::cms::VirgilCMSContentInfo);
    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::VirgilCustomParams);
#endif

    SECTION_CONTRACT_COPY_AND_MOVE(virgil::crypto::VirgilKeyPair);
}
