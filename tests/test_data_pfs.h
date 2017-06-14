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

#include "json.hpp"

#include <fstream>
#include <functional>
#include <cassert>

namespace virgil { namespace crypto { namespace pfs { namespace test { namespace data {

using namespace std::placeholders;
using json = nlohmann::json;

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
inline R optional_test_data(const json& value, ObtainValueFunc obtainValueFunc) {
    if (value.is_null()) {
        return R();
    }
    return obtainValueFunc(value);
}

inline TestCase readTestCase(const char* fileName) {
    assert(fileName && "File name for loading test data is not defined.");

    std::ifstream testDataFile(fileName);
    json testData;
    testDataFile >> testData;

    return TestCase {
            FakeRandom(base64decode(testData["Salt"].get<std::string>())),
            VirgilPFSInitiatorPublicInfo(
                    VirgilPFSPublicKey(private2public(base64decode(testData["ICa"].get<std::string>()))),
                    VirgilPFSPublicKey(private2public(base64decode(testData["EKa"].get<std::string>())))),
            VirgilPFSInitiatorPrivateInfo(
                    VirgilPFSPrivateKey(base64decode(testData["ICa"].get<std::string>())),
                    VirgilPFSPrivateKey(base64decode(testData["EKa"].get<std::string>()))),
            VirgilPFSResponderPublicInfo(
                    VirgilPFSPublicKey(private2public(base64decode(testData["ICb"].get<std::string>()))),
                    VirgilPFSPublicKey(private2public(base64decode(testData["LTCb"].get<std::string>()))),
                    optional_test_data<VirgilPFSPublicKey>(
                            testData["OTCb"], [](const json& value) {
                                    return VirgilPFSPublicKey(private2public(base64decode(value.get<std::string>())));
                            })),
            VirgilPFSResponderPrivateInfo(
                    VirgilPFSPrivateKey(base64decode(testData["ICb"].get<std::string>())),
                    VirgilPFSPrivateKey(base64decode(testData["LTCb"].get<std::string>())),
                    optional_test_data<VirgilPFSPrivateKey>(
                            testData["OTCb"], [](const json& value) {
                                    return VirgilPFSPrivateKey(base64decode(value.get<std::string>()));
                            })),
            VirgilPFSSession(
                    base64decode(testData["SessionID"].get<std::string>()),
                    base64decode(testData["SKa"].get<std::string>()),
                    base64decode(testData["SKb"].get<std::string>()),
                    base64decode(testData["AD"].get<std::string>())),
            VirgilPFSSession(
                    base64decode(testData["SessionID"].get<std::string>()),
                    base64decode(testData["SKb"].get<std::string>()),
                    base64decode(testData["SKa"].get<std::string>()),
                    base64decode(testData["AD"].get<std::string>())),
            base64decode(testData["AdditionalData"].get<std::string>()),
            base64decode(testData["Plaintext"].get<std::string>()),
            VirgilPFSEncryptedMessage(
                    base64decode(testData["SessionID"].get<std::string>()),
                    base64decode(testData["Salt"].get<std::string>()),
                    base64decode(testData["Ciphertext"].get<std::string>()))
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
