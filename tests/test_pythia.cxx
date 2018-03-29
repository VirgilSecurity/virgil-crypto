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
        "0687AC42F1B4B1C1B8427267041F6F723B57845FF537F1F7290A1897FAA9767C175CD7F612BA53DEF7B2A2DEA9"
        "3B55580782D8E1A4FD00231D642ABF792A9AEB870C258CA645E8C719EBFBF96F8713EB9D118A944665C7CE475B"
        "8C0EA7AA5B3E0C2C7BC16439DB5ADB730AAD872404EBBB947278E27CD1C0358CF410E97CE460738D778D6C7C6A"
        "9CA055296B91C4CBDB0C2FC0F4C2933B82FB53F742409D8B9F819A8436993164FA721AA69E626CF52AB71FE521"
        "3EF7B0CB1D1B742AE6000E740716929E7A00A5855D1556208215F8793D288D089370CB8A67C18DACFF0C63706D"
        "D61A0D8F09CBBB0C12E64F133640CB1239F36AE48DDC72CFCDACA6F5383D8D4BDCDCAA8C13EE809D4FA850C76A"
        "81965916AFDE6CDB8E4BD41EADAC9D91E084161D917B6A9268C6A991A217ED0F4E75738F53607FA23E20D8B184"
        "A4DDAC3F36ABB4248B900ED9DCD320FDDCD943151E0C6F2C509364C02F401CB67545E3F730FF7DD31AF3E729AD"
        "AB669BDF09F65EBC5114FA35ECE725AA9658960F361234AD");

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

    auto transformResult = pythia.transform(
            blindResult.blindedPassword(), kTransformationKeyID, kTweek, kPythiaSecret,
            kPythiaScopeSecret);

    auto deblindResult =
            pythia.deblind(transformResult.transformedPassword(), blindResult.blindingSecret());

    REQUIRE(bytes2hex(kDeblindedPassword) == bytes2hex(deblindResult.deblindedPassword()));
}

SCENARIO("VirgilPythia: prove / verify", "[pythia]") {
    VirgilPythia pythia;

    auto blindResult = pythia.blind(kPassword);

    auto transformResult = pythia.transform(
            blindResult.blindedPassword(), kTransformationKeyID, kTweek, kPythiaSecret,
            kPythiaScopeSecret);

    auto proveResult = pythia.prove(
            transformResult.transformedPassword(), blindResult.blindedPassword(),
            transformResult.transformedTweak(), transformResult.transformationPrivateKey());

    auto verifyResult = pythia.verify(
            transformResult.transformedPassword(), blindResult.blindedPassword(), kTweek,
            proveResult.transformationPublicKey(), proveResult.proofValueC(),
            proveResult.proofValueU());

    REQUIRE(true == verifyResult.verified());
}


SCENARIO("VirgilPythia: update password token", "[pythia]") {
    VirgilPythia pythia;

    auto blindResult = pythia.blind(kPassword);

    auto transformResult = pythia.transform(
            blindResult.blindedPassword(), kTransformationKeyID, kTweek, kPythiaSecret,
            kPythiaScopeSecret);

    auto deblindResult =
            pythia.deblind(transformResult.transformedPassword(), blindResult.blindingSecret());

    auto passwordUpdateTokenResult = pythia.getPasswordUpdateToken(
            kTransformationKeyID, kPythiaSecret, kPythiaScopeSecret, kTransformationKeyID,
            kNewPythiaSecret, kNewPythiaScopeSecret);

    auto updatedDeblindPasswordResult = pythia.updateDeblindedWithToken(
            deblindResult.deblindedPassword(), passwordUpdateTokenResult.passwordUpdateToken());

    auto newTransformResult = pythia.transform(
            blindResult.blindedPassword(), kTransformationKeyID, kTweek, kNewPythiaSecret,
            kNewPythiaScopeSecret);

    auto newDeblindResult =
            pythia.deblind(newTransformResult.transformedPassword(), blindResult.blindingSecret());

    REQUIRE(bytes2hex(updatedDeblindPasswordResult.updatedDeblindedPassword()) ==
            bytes2hex(newDeblindResult.deblindedPassword()));

    auto proveResult = pythia.prove(
            newTransformResult.transformedPassword(), blindResult.blindedPassword(),
            newTransformResult.transformedTweak(), newTransformResult.transformationPrivateKey());

    auto verifyResult = pythia.verify(
            newTransformResult.transformedPassword(), blindResult.blindedPassword(), kTweek,
            proveResult.transformationPublicKey(), proveResult.proofValueC(),
            proveResult.proofValueU());

    REQUIRE(true == verifyResult.verified());

    REQUIRE(bytes2hex(proveResult.transformationPublicKey()) ==
            bytes2hex(passwordUpdateTokenResult.updatedTransformationPublicKey()));
}

#endif // VIRGIL_CRYPTO_FEATURE_PYTHIA
