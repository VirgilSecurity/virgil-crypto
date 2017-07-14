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

#ifndef VIRGIL_CRYPTO_PFS_TEST_DATA_PFS_H
#define VIRGIL_CRYPTO_PFS_TEST_DATA_PFS_H

#include <virgil/crypto/pfs/VirgilPFS.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include <fstream>
#include <functional>
#include <cassert>

namespace virgil { namespace crypto { namespace pfs { namespace test { namespace data {

using namespace std::placeholders;
using JsonDocument = rapidjson::Document;
using JsonValue = rapidjson::Value;
using JsonFileStream = rapidjson::IStreamWrapper;

auto base64decode = virgil::crypto::foundation::VirgilBase64::decode;
auto private2public = std::bind(virgil::crypto::VirgilKeyPair::extractPublicKey, _1, VirgilByteArray());

class FakeRandom {
public:
    explicit FakeRandom(VirgilByteArray randomData)
            : randomData_(std::move(randomData)) {}

    VirgilByteArray randomize(size_t bytesNum) {
        assert(randomData_.size() <= bytesNum && "Fake random contains less data then requested.");
        return VirgilByteArray(randomData_.cbegin(), randomData_.cbegin() + bytesNum);
    }

private:
    VirgilByteArray randomData_;
};

struct TestCase {
    VirgilOperationRandom random;
    VirgilPFSInitiatorPublicInfo initiatorPublicInfo;
    VirgilPFSInitiatorPrivateInfo initiatorPrivateInfo;
    VirgilPFSResponderPublicInfo responderPublicInfo;
    VirgilPFSResponderPrivateInfo responderPrivateInfo;
    VirgilPFSSession initiatorSession;
    VirgilPFSSession responderSession;
    VirgilByteArray additionalData;
    VirgilByteArray plainText;
    VirgilPFSEncryptedMessage encryptedMessage;
};

template<typename R, typename ObtainValueFunc>
inline R optional_test_data(const JsonValue& jsonValue, const char* key, ObtainValueFunc obtainValueFunc) {
    if (jsonValue.HasMember(key)) {
        return obtainValueFunc(jsonValue[key]);
    }
    return R();
}

inline TestCase readTestCase(const char* fileName) {
    assert(fileName && "File name for loading test data is not defined.");

    std::ifstream testDataFile(fileName);
    JsonFileStream testDataFileJsonStream(testDataFile);
    JsonDocument testData;
    testData.ParseStream(testDataFileJsonStream);

    return TestCase {
            FakeRandom(base64decode(testData["Salt"].GetString())),
            VirgilPFSInitiatorPublicInfo(
                    VirgilPFSPublicKey(private2public(base64decode(testData["ICa"].GetString()))),
                    VirgilPFSPublicKey(private2public(base64decode(testData["EKa"].GetString())))),
            VirgilPFSInitiatorPrivateInfo(
                    VirgilPFSPrivateKey(base64decode(testData["ICa"].GetString())),
                    VirgilPFSPrivateKey(base64decode(testData["EKa"].GetString()))),
            VirgilPFSResponderPublicInfo(
                    VirgilPFSPublicKey(private2public(base64decode(testData["ICb"].GetString()))),
                    VirgilPFSPublicKey(private2public(base64decode(testData["LTCb"].GetString()))),
                    optional_test_data<VirgilPFSPublicKey>(
                            testData, "OTCb", [](const JsonValue& value) {
                                    return VirgilPFSPublicKey(private2public(base64decode(value.GetString())));
                            })),
            VirgilPFSResponderPrivateInfo(
                    VirgilPFSPrivateKey(base64decode(testData["ICb"].GetString())),
                    VirgilPFSPrivateKey(base64decode(testData["LTCb"].GetString())),
                    optional_test_data<VirgilPFSPrivateKey>(
                            testData, "OTCb", [](const JsonValue& value) {
                                    return VirgilPFSPrivateKey(base64decode(value.GetString()));
                            })),
            VirgilPFSSession(
                    base64decode(testData["SessionID"].GetString()),
                    base64decode(testData["SKa"].GetString()),
                    base64decode(testData["SKb"].GetString()),
                    base64decode(testData["AD"].GetString())),
            VirgilPFSSession(
                    base64decode(testData["SessionID"].GetString()),
                    base64decode(testData["SKb"].GetString()),
                    base64decode(testData["SKa"].GetString()),
                    base64decode(testData["AD"].GetString())),
            base64decode(testData["AdditionalData"].GetString()),
            base64decode(testData["Plaintext"].GetString()),
            VirgilPFSEncryptedMessage(
                    base64decode(testData["SessionID"].GetString()),
                    base64decode(testData["Salt"].GetString()),
                    base64decode(testData["Ciphertext"].GetString()))
    };
}

inline TestCase getTestCaseWithOTC() {
    static TestCase testCase = readTestCase("data/test_data_pfs_with_otc.json");
    return testCase;
}

inline TestCase getCaseWithoutOTC() {
    static TestCase testCase = readTestCase("data/test_data_pfs_without_otc.json");
    return testCase;
}

}}}}}

#endif //VIRGIL_CRYPTO_PFS_TEST_DATA_PFS_H
