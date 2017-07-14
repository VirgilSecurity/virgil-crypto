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

#include "catch.hpp"

#include "test_data_pfs.h"

using namespace virgil::crypto::pfs;
using virgil::crypto::bytes2hex;

SCENARIO("PFS start Initiator session.", "[pfs]") {

    auto testFunction = [](const test::data::TestCase& testData) {
            auto pfs = VirgilPFS();
            auto session = pfs.startInitiatorSession(
                    testData.initiatorPrivateInfo,
                    testData.responderPublicInfo,
                    testData.additionalData);
            auto testSession = testData.initiatorSession;
            REQUIRE(bytes2hex(session.getIdentifier()) == bytes2hex(testSession.getIdentifier()));
            REQUIRE(bytes2hex(session.getEncryptionSecretKey()) == bytes2hex(testSession.getEncryptionSecretKey()));
            REQUIRE(bytes2hex(session.getDecryptionSecretKey()) == bytes2hex(testSession.getDecryptionSecretKey()));
            REQUIRE(bytes2hex(session.getAdditionalData()) == bytes2hex(testSession.getAdditionalData()));
    };

    GIVEN("One-time key.") {
        testFunction(test::data::getTestCaseWithOTC());
    }

    GIVEN("No one-time key.") {
        testFunction(test::data::getCaseWithoutOTC());
    }
}

SCENARIO("PFS start Responder session.", "[pfs]") {

    auto testFunction = [](const test::data::TestCase& testData) {
            auto pfs = VirgilPFS();
            auto session = pfs.startResponderSession(
                    testData.responderPrivateInfo,
                    testData.initiatorPublicInfo,
                    testData.additionalData);
            auto testSession = testData.responderSession;
            REQUIRE(bytes2hex(session.getIdentifier()) == bytes2hex(testSession.getIdentifier()));
            REQUIRE(bytes2hex(session.getEncryptionSecretKey()) == bytes2hex(testSession.getEncryptionSecretKey()));
            REQUIRE(bytes2hex(session.getDecryptionSecretKey()) == bytes2hex(testSession.getDecryptionSecretKey()));
            REQUIRE(bytes2hex(session.getAdditionalData()) == bytes2hex(testSession.getAdditionalData()));
    };

    GIVEN("One-time key.") {
        testFunction(test::data::getTestCaseWithOTC());
    }

    GIVEN("No one-time key.") {
        testFunction(test::data::getCaseWithoutOTC());
    }
}

SCENARIO("PFS encrypt.", "[pfs]") {

    auto testFunction = [](const test::data::TestCase& testData) {
            auto pfs = VirgilPFS();
            pfs.setRandom(testData.random);
            pfs.startInitiatorSession(
                    testData.initiatorPrivateInfo,
                    testData.responderPublicInfo,
                    testData.additionalData);

            auto encryptedMessage = pfs.encrypt(testData.plainText);
            REQUIRE(bytes2hex(encryptedMessage.getSessionIdentifier()) ==
                    bytes2hex(testData.encryptedMessage.getSessionIdentifier()));
            REQUIRE(bytes2hex(encryptedMessage.getSalt()) == bytes2hex(testData.encryptedMessage.getSalt()));
            REQUIRE(bytes2hex(encryptedMessage.getCipherText()) ==
                    bytes2hex(testData.encryptedMessage.getCipherText()));
    };

    GIVEN("One-time key.") {
        testFunction(test::data::getTestCaseWithOTC());
    }

    GIVEN("No one-time key.") {
        testFunction(test::data::getCaseWithoutOTC());
    }
}


SCENARIO("PFS decrypt.", "[pfs]") {

    auto testFunction = [](const test::data::TestCase& testData) {
            auto pfs = VirgilPFS();
            pfs.setRandom(testData.random);
            pfs.startResponderSession(
                    testData.responderPrivateInfo,
                    testData.initiatorPublicInfo,
                    testData.additionalData);

            auto plainText = pfs.decrypt(testData.encryptedMessage);
            REQUIRE(bytes2hex(plainText) == bytes2hex(testData.plainText));
    };

    GIVEN("One-time key.") {
        testFunction(test::data::getTestCaseWithOTC());
    }

    GIVEN("No one-time key.") {
        testFunction(test::data::getCaseWithoutOTC());
    }
}
