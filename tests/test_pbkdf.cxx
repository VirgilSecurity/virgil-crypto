/**
 * Copyright (C) 2016 Virgil Security Inc.
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
 * @file test_pbkdf.cxx
 * @brief Covers class VirgilPBKDF
 */

#include "catch.hpp"

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilPBKDF.h>

using virgil::crypto::str2bytes;
using virgil::crypto::hex2bytes;
using virgil::crypto::bytes2hex;
using virgil::crypto::VirgilByteArray;

using virgil::crypto::foundation::VirgilPBKDF;

static void test_pbkdf_derive_helper(VirgilPBKDF::Algorithm alg, VirgilPBKDF::Hash hash,
        const char *pwdHex, const char *saltHex, unsigned int iterationCount, size_t outSize,
        const char *expectedKeyHex) {

    VirgilPBKDF pbkdf = VirgilPBKDF(hex2bytes(saltHex), iterationCount);
    pbkdf.setAlgorithm(alg);
    pbkdf.setHash(hash);
    pbkdf.disableRecommendationsCheck();
    VirgilByteArray derivedKey = pbkdf.derive(hex2bytes(pwdHex), outSize);
    REQUIRE(bytes2hex(derivedKey) == std::string(expectedKeyHex));
}

static void test_pbkdf_to_asn1_helper(VirgilPBKDF::Algorithm alg, VirgilPBKDF::Hash hash,
        const char *saltHex, unsigned int iterationCount, const char *expectedAsn1) {

    VirgilPBKDF pbkdf = VirgilPBKDF(hex2bytes(saltHex), iterationCount);
    pbkdf.setAlgorithm(alg);
    pbkdf.setHash(hash);
    VirgilByteArray asn1 = pbkdf.toAsn1();
    REQUIRE(bytes2hex(asn1) == std::string(expectedAsn1));
}

static void test_pbkdf_from_asn1_helper(VirgilPBKDF::Algorithm expectedAlg,
        VirgilPBKDF::Hash expectedHash,
        const char *expectedSaltHex, unsigned int expectedIterationCount, const char *asn1) {

    VirgilPBKDF pbkdf = VirgilPBKDF();
    pbkdf.fromAsn1(hex2bytes(asn1));

    REQUIRE(pbkdf.getAlgorithm() == expectedAlg);
    REQUIRE(pbkdf.getHash() == expectedHash);
    REQUIRE(pbkdf.getIterationCount() == expectedIterationCount);
    REQUIRE(bytes2hex(pbkdf.getSalt()) == std::string(expectedSaltHex));
}

TEST_CASE("PBKDF2 Success", "[PBKDF]") {
    VirgilPBKDF::Algorithm pbkdfType = VirgilPBKDF::Algorithm_PBKDF2;

    SECTION("PBKDF2 RFC 6070 Test Vector #1 (SHA1)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA1,
                "70617373776f7264", "73616c74", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    }

    SECTION("PBKDF2 RFC 6070 Test Vector #2 (SHA1)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA1,
                "70617373776f7264", "73616c74", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }

    SECTION("PBKDF2 RFC 6070 Test Vector #3 (SHA1)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA1,
                "70617373776f7264", "73616c74", 4096, 20, "4b007901b765489abead49d926f721d065a429c1");
    }

    SECTION("PBKDF2 RFC 6070 Test Vector #5 (SHA1)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA1,
                "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
    }

    SECTION("PBKDF2 RFC 6070 Test Vector #6 (SHA1)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA1,
                "7061737300776f7264", "7361006c74", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3");
    }

    SECTION("PBKDF2 Custom Test Vector #1 (SHA224)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA224,
                "70617373776f7264", "73616c74", 1, 28, "3c198cbdb9464b7857966bd05b7bc92bc1cc4e6e63155d4e490557fd");
    }

    SECTION("PBKDF2 Custom Test Vector #2 (SHA224)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA224,
                "70617373776f7264", "73616c74", 2, 28, "93200ffa96c5776d38fa10abdf8f5bfc0054b9718513df472d2331d2");
    }

    SECTION("PBKDF2 Custom Test Vector #3 (SHA224)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA224,
                "70617373776f7264", "73616c74", 4096, 28, "218c453bf90635bd0a21a75d172703ff6108ef603f65bb821aedade1");
    }

    SECTION("PBKDF2 Custom Test Vector #5 (SHA224)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA224,
                "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 4096, 34, "056c4ba438ded91fc14e0594e6f52b87e1f3690c0dc0fbc05784ed9a754ca780e6c0");
    }

    SECTION("PBKDF2 Custom Test Vector #6 (SHA224)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA224,
                "7061737300776f7264", "7361006c74", 4096, 16, "9b4011b641f40a2a500a31d4a392d15c");
    }

    SECTION("PBKDF2 Custom Test Vector #1 (SHA256)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA256,
                "70617373776f7264", "73616c74", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    }

    SECTION("PBKDF2 Custom Test Vector #2 (SHA256)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA256,
                "70617373776f7264", "73616c74", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    }

    SECTION("PBKDF2 Custom Test Vector #3 (SHA256)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA256,
                "70617373776f7264", "73616c74", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    }

    SECTION("PBKDF2 Custom Test Vector #5 (SHA256)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA256,
                "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 4096, 40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
    }

    SECTION("PBKDF2 Custom Test Vector #6 (SHA256)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA256,
                "7061737300776f7264", "7361006c74", 4096, 16, "89b69d0516f829893c696226650a8687");
    }

    SECTION("PBKDF2 Custom Test Vector #1 (SHA384)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA384,
                "70617373776f7264", "73616c74", 1, 48, "c0e14f06e49e32d73f9f52ddf1d0c5c7191609233631dadd76a567db42b78676b38fc800cc53ddb642f5c74442e62be4");
    }

    SECTION("PBKDF2 Custom Test Vector #2 (SHA384)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA384,
                "70617373776f7264", "73616c74", 2, 48, "54f775c6d790f21930459162fc535dbf04a939185127016a04176a0730c6f1f4fb48832ad1261baadd2cedd50814b1c8");
    }

    SECTION("PBKDF2 Custom Test Vector #3 (SHA384)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA384,
                "70617373776f7264", "73616c74", 4096, 48, "559726be38db125bc85ed7895f6e3cf574c7a01c080c3447db1e8a76764deb3c307b94853fbe424f6488c5f4f1289626");
    }

    SECTION("PBKDF2 Custom Test Vector #5 (SHA384)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA384,
                "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 4096, 60, "819143ad66df9a552559b9e131c52ae6c5c1b0eed18f4d283b8c5c9eaeb92b392c147cc2d2869d58ffe2f7da13d15f8d925721f0ed1afafa24480d55");
    }

    SECTION("PBKDF2 Custom Test Vector #6 (SHA384)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA384,
                "7061737300776f7264", "7361006c74", 4096, 16, "a3f00ac8657e095f8e0823d232fc60b3");
    }

    SECTION("PBKDF2 Custom Test Vector #1 (SHA512)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA512,
                "70617373776f7264", "73616c74", 1, 64, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce");
    }

    SECTION("PBKDF2 Custom Test Vector #2 (SHA512)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA512,
                "70617373776f7264", "73616c74", 2, 64, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e");
    }

    SECTION("PBKDF2 Custom Test Vector #3 (SHA512)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA512,
                "70617373776f7264", "73616c74", 4096, 64, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5");
    }

    SECTION("PBKDF2 Custom Test Vector #5 (SHA512)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA512,
                "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 4096, 80, "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b804f75bdd41494fa324cab24bcc680fb3");
    }

    SECTION("PBKDF2 Custom Test Vector #6 (SHA512)") {
        test_pbkdf_derive_helper(pbkdfType, VirgilPBKDF::Hash_SHA512,
                "7061737300776f7264", "7361006c74", 4096, 16, "9d9e9c4cd21fe4be24d5b8244c759665");
    }
}

TEST_CASE("PBKDF2 corner cases", "[PBKDF]") {
    const unsigned int iterationCountGood = 4096;
    const unsigned int iterationCountBad = 1;
    const unsigned int iterationCountZero = 0;
    const VirgilByteArray pwdGood = str2bytes("password");
    const VirgilByteArray pwdBad = hex2bytes("");
    const VirgilByteArray saltGood = str2bytes("salt");
    const VirgilByteArray saltBad = hex2bytes("");
    const size_t deriveSizeGood = 32;
    const size_t deriveSizeBad = 0;

    SECTION("pass insecure salt") {
        VirgilPBKDF pbkdf = VirgilPBKDF(saltBad, iterationCountGood);
        pbkdf.enableRecommendationsCheck();
        REQUIRE_THROWS(pbkdf.derive(pwdGood, deriveSizeGood));
        pbkdf.disableRecommendationsCheck();
        REQUIRE_NOTHROW(pbkdf.derive(pwdGood, deriveSizeGood));
    }

    SECTION("pass insecure passowrd") {
        VirgilPBKDF pbkdf = VirgilPBKDF(saltGood, iterationCountGood);
        pbkdf.enableRecommendationsCheck();
        REQUIRE_THROWS(pbkdf.derive(pwdBad, deriveSizeGood));
        pbkdf.disableRecommendationsCheck();
        REQUIRE_NOTHROW(pbkdf.derive(pwdBad, deriveSizeGood));
    }

    SECTION("pass insecure iteration count") {
        VirgilPBKDF pbkdf = VirgilPBKDF(saltGood, iterationCountBad);
        pbkdf.enableRecommendationsCheck();
        REQUIRE_THROWS(pbkdf.derive(pwdGood, deriveSizeGood));
        pbkdf.disableRecommendationsCheck();
        REQUIRE_NOTHROW(pbkdf.derive(pwdGood, deriveSizeGood));
    }

    SECTION("pass zero iteration count") {
        VirgilPBKDF pbkdf = VirgilPBKDF(saltGood, iterationCountZero);
        pbkdf.enableRecommendationsCheck();
        REQUIRE_THROWS(pbkdf.derive(pwdGood, deriveSizeGood));
        pbkdf.disableRecommendationsCheck();
        REQUIRE_NOTHROW(pbkdf.derive(pwdGood, deriveSizeGood));
    }

    SECTION("pass zero derived size") {
        VirgilPBKDF pbkdf = VirgilPBKDF(saltGood, iterationCountGood);
        REQUIRE_NOTHROW(pbkdf.derive(pwdGood, deriveSizeBad));
    }
}

TEST_CASE("PBKDF2 to ASN.1", "[PBKDF]") {
    VirgilPBKDF::Algorithm pbkdfType = VirgilPBKDF::Algorithm_PBKDF2;

    SECTION("digest:SHA1, iteration count:1, salt:salt1") {
        test_pbkdf_to_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA1,
                "73616c7431", 0x01, "302006092a864886f70d01050c3013040573616c7431020101300706052b0e03021a");
    }
    SECTION("digest:SHA224, iteration count:15, salt:salt2") {
        test_pbkdf_to_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA224,
                "73616c7432", 0x0F, "302406092a864886f70d01050c3017040573616c743202010f300b0609608648016503040204");
    }
    SECTION("digest:SHA256, iteration count:255, salt:salt3") {
        test_pbkdf_to_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA256,
                "73616c7433", 0xFF, "302506092a864886f70d01050c3018040573616c7433020200ff300b0609608648016503040201");
    }
    SECTION("digest:SHA384, iteration count:65535, salt:salt4") {
        test_pbkdf_to_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA384,
                "73616c7434", 0xFFFF, "302606092a864886f70d01050c3019040573616c7434020300ffff300b0609608648016503040202");
    }
    SECTION("digest:SHA512, iteration count:268435455, salt:salt5") {
        test_pbkdf_to_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA512,
                "73616c7435", 0x0FFFFFFF, "302706092a864886f70d01050c301a040573616c743502040fffffff300b0609608648016503040203");
    }
}

TEST_CASE("PBKDF2 from ASN.1", "[PBKDF]") {
    VirgilPBKDF::Algorithm pbkdfType = VirgilPBKDF::Algorithm_PBKDF2;

    SECTION("digest:SHA1, iteration count:1, salt:salt1") {
        test_pbkdf_from_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA1,
                "73616c7431", 0x01, "302206092a864886f70d01050c3013040573616c7431020101300706052b0e03021a0500");
    }
    SECTION("digest:SHA224, iteration count:15, salt:salt2") {
        test_pbkdf_from_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA224,
                "73616c7432", 0x0F, "302406092a864886f70d01050c3017040573616c743202010f300b0609608648016503040204");
    }
    SECTION("digest:SHA256, iteration count:255, salt:salt3") {
        test_pbkdf_from_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA256,
                "73616c7433", 0xFF, "302506092a864886f70d01050c3018040573616c7433020200ff300b0609608648016503040201");
    }
    SECTION("digest:SHA384, iteration count:65535, salt:salt4") {
        test_pbkdf_from_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA384,
                "73616c7434", 0xFFFF, "302606092a864886f70d01050c3019040573616c7434020300ffff300b0609608648016503040202");
    }
    SECTION("digest:SHA512, iteration count:268435455, salt:salt5") {
        test_pbkdf_from_asn1_helper(pbkdfType, VirgilPBKDF::Hash_SHA512,
                "73616c7435", 0x0FFFFFFF, "302706092a864886f70d01050c301a040573616c743502040fffffff300b0609608648016503040203");
    }
}

TEST_CASE("PBKDF2 with default output size", "[PBKDF]") {
    const VirgilByteArray salt = str2bytes("salt");
    const VirgilByteArray pwd = str2bytes("password");
    VirgilPBKDF pbkdf(salt);
    SECTION("SHA1") {
        pbkdf.setHash(VirgilPBKDF::Hash_SHA1);
        REQUIRE(pbkdf.derive(pwd).size() == 20);
    }
    SECTION("SHA224") {
        pbkdf.setHash(VirgilPBKDF::Hash_SHA224);
        REQUIRE(pbkdf.derive(pwd).size() == 28);
    }
    SECTION("SHA256") {
        pbkdf.setHash(VirgilPBKDF::Hash_SHA256);
        REQUIRE(pbkdf.derive(pwd).size() == 32);
    }
    SECTION("SHA384") {
        pbkdf.setHash(VirgilPBKDF::Hash_SHA384);
        REQUIRE(pbkdf.derive(pwd).size() == 48);
    }
    SECTION("SHA512") {
        pbkdf.setHash(VirgilPBKDF::Hash_SHA512);
        REQUIRE(pbkdf.derive(pwd).size() == 64);
    }
}
