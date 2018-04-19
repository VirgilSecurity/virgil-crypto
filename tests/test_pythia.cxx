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
 * @file test_pythia_c.cxx
 * @brief Test C implementation of the Pythia algorithm
 */

#include "catch.hpp"

#if VIRGIL_CRYPTO_FEATURE_PYTHIA

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/pythia/VirgilPythia.h>

using virgil::crypto::bytes2hex;
using virgil::crypto::hex2bytes;
using virgil::crypto::str2bytes;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::pythia::VirgilPythia;

static const VirgilByteArray kDeblindedPassword = hex2bytes(
        "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992e4e6f705ac3f0a915"
        "d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c2666591134c645d45ed8"
        "c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67c38279e3b9fe32f6c407803"
        "11f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d19bfa2f789024333976c69fbe9e"
        "24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c2da7ea280550baccd55dadd70873a"
        "063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e1145944328266616cd00f8a616f0e79e52ddd"
        "2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b62af87c1d45ca994d23f908f7898a3f44ca"
        "7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca68eb783c89b0dc9d92392f453c650e9f09232b9"
        "fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c");

static const VirgilByteArray kPassword = str2bytes("password");
static const VirgilByteArray kTransformationKeyID = str2bytes("virgil.com");
static const VirgilByteArray kTweek = str2bytes("alice");
static const VirgilByteArray kPythiaSecret = str2bytes("master secret");
static const VirgilByteArray kNewPythiaSecret = str2bytes("new master secret");
static const VirgilByteArray kPythiaScopeSecret = str2bytes("server secret");
static const VirgilByteArray kNewPythiaScopeSecret = str2bytes("new server secret");

SCENARIO("VirgilPythia: init", "[pythia]") {
    VirgilPythia pythia;
}

SCENARIO("VirgilPythia: blind / deblind", "[pythia]") {
    VirgilPythia pythia;

    auto blindResult = pythia.blind(kPassword);

    auto tranfKP = pythia.computeTransformationKeyPair(kTransformationKeyID, kPythiaSecret, kPythiaScopeSecret);

    auto transformResult = pythia.transform(
            blindResult.blindedPassword(), kTweek, tranfKP.privateKey());

    auto deblindResult =
            pythia.deblind(transformResult.transformedPassword(), blindResult.blindingSecret());

    REQUIRE(bytes2hex(kDeblindedPassword) == bytes2hex(deblindResult));
}

SCENARIO("VirgilPythia: prove / verify", "[pythia]") {
    VirgilPythia pythia;

    auto blindResult = pythia.blind(kPassword);

    auto tranfKP = pythia.computeTransformationKeyPair(kTransformationKeyID, kPythiaSecret, kPythiaScopeSecret);

    auto transformResult = pythia.transform(
            blindResult.blindedPassword(), kTweek, tranfKP.privateKey());

    auto proveResult = pythia.prove(
            transformResult.transformedPassword(), blindResult.blindedPassword(),
            transformResult.transformedTweak(), tranfKP);

    auto verifyResult = pythia.verify(
            transformResult.transformedPassword(), blindResult.blindedPassword(), kTweek,
            tranfKP.publicKey(), proveResult.proofValueC(),
            proveResult.proofValueU());

    REQUIRE(true == verifyResult.verified());
}


SCENARIO("VirgilPythia: update password token", "[pythia]") {
    VirgilPythia pythia;

    auto blindResult = pythia.blind(kPassword);

    auto tranfKP = pythia.computeTransformationKeyPair(kTransformationKeyID, kPythiaSecret, kPythiaScopeSecret);

    auto transformResult = pythia.transform(
            blindResult.blindedPassword(), kTweek, tranfKP.privateKey());

    auto deblindResult =
            pythia.deblind(transformResult.transformedPassword(), blindResult.blindingSecret());

    auto newTranfKP = pythia.computeTransformationKeyPair(kTransformationKeyID, kNewPythiaSecret, kNewPythiaScopeSecret);

    auto passwordUpdateTokenResult = pythia.getPasswordUpdateToken(tranfKP.privateKey(), newTranfKP.privateKey());

    auto updatedDeblindPasswordResult = pythia.updateDeblindedWithToken(
            deblindResult, passwordUpdateTokenResult);

    auto newTransformResult = pythia.transform(
            blindResult.blindedPassword(), kTweek, newTranfKP.privateKey());

    auto newDeblindResult =
            pythia.deblind(newTransformResult.transformedPassword(), blindResult.blindingSecret());

    REQUIRE(bytes2hex(updatedDeblindPasswordResult) ==
            bytes2hex(newDeblindResult));

    auto proveResult = pythia.prove(
            newTransformResult.transformedPassword(), blindResult.blindedPassword(),
            newTransformResult.transformedTweak(), newTranfKP);

    auto verifyResult = pythia.verify(
            newTransformResult.transformedPassword(), blindResult.blindedPassword(), kTweek,
            newTranfKP.publicKey(), proveResult.proofValueC(),
            proveResult.proofValueU());

    REQUIRE(true == verifyResult.verified()); }

#endif // VIRGIL_CRYPTO_FEATURE_PYTHIA
