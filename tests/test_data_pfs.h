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
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <cassert>

namespace virgil { namespace crypto { namespace pfs { namespace test { namespace data {

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

auto base64decode = virgil::crypto::foundation::VirgilBase64::decode;

struct TestCase {
    VirgilOperationRandom random;
    VirgilPFSInitiatorPublicInfo initiatorPublicInfo;
    VirgilPFSInitiatorPrivateInfo initiatorPrivateInfo;
    VirgilPFSResponderPublicInfo responderPublicInfo;
    VirgilPFSResponderPrivateInfo responderPrivateInfo;
    VirgilPFSSession initiatorSession;
    VirgilPFSSession responderSession;
    VirgilByteArray plainText;
    VirgilPFSEncryptedMessage encryptedMessage;
};

inline TestCase getTestCaseWithOTC() {
    static TestCase testCase{
            .random = FakeRandom(base64decode("U+FlYtEnx8tB1CaO7omd3g==")),
            .initiatorPublicInfo = VirgilPFSInitiatorPublicInfo(
                    /* identifier */
                    "4c4a1f046c7fba486db78f007c8220b3b9febf3b5f9beb13192f42d4a56e69fd",
                    /* identityPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEA2dxpu/KAjpDN4SUjiju8IjavR8HIPgQlT8s+uYsmP0o=")),
                    /* ephemeralPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEA8NYtIwY9hTSXu95ML0810CeCtYTv5NCtWh3H2Mx3yW8="))),
            .initiatorPrivateInfo = VirgilPFSInitiatorPrivateInfo(
                    /* identifier */
                    "4c4a1f046c7fba486db78f007c8220b3b9febf3b5f9beb13192f42d4a56e69fd",
                    /* identityPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIGD5GI3hfWlVkN3NRRpFakrsYLrc2MKQms447y0yZb2I")),
                    /* ephemeralPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIFKWKLAWp9a7AHKh8+q40FetLqG6gFuWJ9HZn1DLFHoP"))),
            .responderPublicInfo = VirgilPFSResponderPublicInfo(
                    /* identifier */
                    "c1427191d3ad91055e46c08711fe42621c5d2ebd1b459e408bc27204d5137c2a",
                    /* identityPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEABaqQR+SH3qgua/8r7wxDI3mf26IdhVFScW1VayjgQIs=")),
                    /* longTermPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEAepJUu3VKTnMwX2y+LjkZ+A8UJLPbLZ5g27gAncROSDQ=")),
                    /* oneTimePublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEAjFGHdX8mo1662k/88sNnxy9YSKnXN39IzwcHa2h07OE="))),
            .responderPrivateInfo = VirgilPFSResponderPrivateInfo(
                    /* identifier */
                    "c1427191d3ad91055e46c08711fe42621c5d2ebd1b459e408bc27204d5137c2a",
                    /* identityPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIIGUqUPiUZE0bAhMtrlInLD2M0LlpLf5lANEveWkghCR")),
                    /* longTermPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIOr81pHtYGcx0sacPrPmd3Csw2RUceZIS+KYURhtUah4")),
                    /* oneTimePrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIE9DqGtQLveTVeHR3jDY0Fqd1vadTYaOu2HduxVLXk3F"))),
            .initiatorSession = VirgilPFSSession(
                    /* identifier */
                    base64decode("gp+dT1HIg96PW0fXTYKY+Cxt5JfDlQtahF+iKH61zeU="),
                    /* encryptionSecretKey */
                    base64decode(
                            "ZRY0VdjjK00Qm9GJ1tJbwot3EvzrGWKES/ROukBKN6ZBkr0H2GEKBEmDXrZCoHas1b39ahFi8ZG/UhZojYd8zw=="),
                    /* decryptionSecretKey */
                    base64decode(
                            "Pofh04MctwYCtBeL3eLop3hTkaS9+usin9adeH/QI2YT+RfytXYMA7yeUH86uvFmk1jC59RR02qyhnwrRwXxoQ=="),
                    /* additionalData */
                    base64decode("IsU1DeVQLext/UxhOQTSIr+kPuKl/1I17cb/3JVhc/Q=")),
            .responderSession = VirgilPFSSession(
                    /* identifier */
                    base64decode("gp+dT1HIg96PW0fXTYKY+Cxt5JfDlQtahF+iKH61zeU="),
                    /* encryptionSecretKey */
                    base64decode(
                            "Pofh04MctwYCtBeL3eLop3hTkaS9+usin9adeH/QI2YT+RfytXYMA7yeUH86uvFmk1jC59RR02qyhnwrRwXxoQ=="),
                    /* decryptionSecretKey */
                    base64decode(
                            "ZRY0VdjjK00Qm9GJ1tJbwot3EvzrGWKES/ROukBKN6ZBkr0H2GEKBEmDXrZCoHas1b39ahFi8ZG/UhZojYd8zw=="),
                    /* additionalData */
                    base64decode("IsU1DeVQLext/UxhOQTSIr+kPuKl/1I17cb/3JVhc/Q=")),
            .plainText = base64decode(
                    "Rd3bImATu7n/ZKBIFRq9WStMBF6yVXkQLvL1ipsNBGiZnEDNV2PdQoMuhcUEouI/"
                            "W+O7cI84qFxdCZFfmxgFhlKk1roB7j+rKgawsxQ7quPzHO7MnNRPJYbthTDZC8yf"
                            "UtTCSNUUaQL9PwCX/MixCfyoH6d3Thp5+ZggnkSd6LOdHKxnb3HzV9WOgarqNUok"
                            "duU806BiX4JGUQ8JPlHI+JCunNmm+EdUGkGLP9Fy8QbfENHUQpeJppjru/n/6NMp"
                            "sKWsFz7E6y5Maf2551yn6tSpjkp++4c3D9BdfUpXNFprpuB2bzdarP2HY2FhLDaT"
                            "tywWkUEnK6VGbtgfKlGaNxFs5ESBILbu35bClCtVQWG19ef9wfVGerlQQz+32ks1"
                            "HMyvbGBPsHTRAy0O+ieqXKI+TEq5T9fAEDDHfvBmmrBOPra2bFqCWJjFRHIE4H6k"
                            "xmPwwoAsNzHXIfP4ZyG+KgXd74I16QtwCstgpk0DjYmU+RKUq2SDX5qzxDqXONnD"
                            "6DUYL9FtmHAAh4QyI97SULt2M75oNk//nl2gvWHat4mP6d/1ENyjT5u8IySwzhTd"
                            "UNhbxhR27oOVqZcB4vNY6OpldBV1XZl87XmhN02KN1PfejTLT3xh1aoe/bSAwpoQ"
                            "0A2IyTqRkviBy8Q6YVJfmvik07iMdD9K3GrnCySosxSo2OxR88yMwtZcdiPQYHXK"
                            "KmuS/Ao9GVv3J2wrmnON9K9TNdbf0XphJCwJ39NX/AfvrguJs3V4uJN7Pz++KqYJ"
                            "2MCkfjB8DUJwFYhgFpOYPrLQchf+n5WLm1FPoBurctyJSHOTjLNVRfsRH2lmPgD0"
                            "/BUt/EtqsM4LnLq8dIXqujYUTFkXpHdmxxaPZFDTQVSqp6xMSWBATY1ocW0Jkxfu"
                            "4UEvdmriyOeT0exf5Z6rUxplgWYexvly93Geq7M7qYoqGxEbNKo38TxChDGA9wbI"
                            "usn6A7FI87RsQ8GRJNhHK0Nk4r5AVxVI1q6km92AEdkpAqlVXA8+2J6DFbbzRtMh"
                            "B2hp3gWgi1u15t9ZAPd+i2Xd2NlV0US1abTqneTCztaYvu+d/IfUhO7k4BljVZEJ"
                            "Hls1EkT0tZaBz+2wWEjpRx2c3Hxj7UvIr5/4bDTYpqlGvg9SAPfVM4F6BVOA24Jc"
                            "ySyzTi7Qd/zQOUb3dcbTK9RWFUXnpTkuMMAb2oOtkQG/Rjxo1m+7EcniUSu37/Xk"
                            "+4fLYGJaKZtKsqhQ6wFwVJ6uOVM2jiNJ1NrFTA3fgOn1/CGSpmHl9KyP0aIJPwDM"
                            "ig3NORf6utL6AEcIGt6Cq5iQxDSqhifmlcHftZLKom1GavvvpOBAjuI4Z+DNEXDP"
                            "xKbf/IXNZKRtcJ+XDBEAb6Y="),
            .encryptedMessage = VirgilPFSEncryptedMessage(
                    /* sessionIdentifier */
                    base64decode("gp+dT1HIg96PW0fXTYKY+Cxt5JfDlQtahF+iKH61zeU="),
                    /* salt */
                    base64decode("U+FlYtEnx8tB1CaO7omd3g=="),
                    /* cipherText */
                    base64decode(
                            "uTRqZQQMDn/NUb/gtYk4T4t5UgsMK5++S6hxZGgv28hX1rFPQH/jTzoQjekQEmKz"
                                    "tvNMwXSencTJFjwQD+VVmOSyPw/EuN53fTgG+gscwmhZu7BZaChGI4mOuqaVo2kZ"
                                    "E2T1aiEP8lBe1SasiGdZ+szSx5BkuLqkN0B5C2iymT06IiWvYtLWGuR2SXSJHwvT"
                                    "0hj0hw8w2XGAqsd4UBTMc0R5SwDvLJr7rJnWgTRGGTKFKMd7vDk9y71MEB1wahO9"
                                    "hh5Bv4HGvEWuuTvo2G+espOcNI6h9T4xOzo5PsLETlP2V0pCjN+k/7dGQnoIK8H8"
                                    "FtTB63BbXLWWU4tXw2RBKH+atcDzGOXb8h8Toc3QjNKf0RpkeVpEvysmts2JUoL+"
                                    "rilnbHBHPv5w2UOwOaVv8tzj/o70RXr/89e70JFD4Q7CHeVer6/XCDkHqfLA1Ney"
                                    "fcB/Hyg0+8Kc/cttjlD2vYA2iSnALB6oFnm8k7JLHw8g3b+P6bqxC1HM3JsnVbSw"
                                    "IPastNnv7eku9A4oncioAyMQdoc/PvG9WGvcbSIrMDRuWf1pvtkfuU29R0Off3+1"
                                    "rwLzYLHsaOFU1qnKuG+bjraR+gf6GYxteQ609xPbkOoeHwtpNNOY9s0NN8Ak/lsf"
                                    "y4QIQ+WXRathH/6nN7DagGQEiaCdfuRmEvHCkj1HLWLSO1zURYJNDmKUhvb/+KAg"
                                    "o98tVcqpaEbr0Mlp9jD7QwYUeAufnBlZ5MJwT/GB2rg1OBCjOCrMzkVedndSD51J"
                                    "RHFYopbj5QKFboYyN7YjMt/Fpk6ztDJL0U/dd+DpiZItAW37l9GB0Phj7CFe5a7H"
                                    "9rlyic+aG+d5rM2u9a+xpYbANRaSEkKf/gQvy6UtowzKxntb+2YFJVhkNOCngqpZ"
                                    "tAeYLCJFrsb8JyvyuhmIEmWhlm+T8CfEZOoVIuLvyV5yXX8tuBh//ch3EL61/c3T"
                                    "Pmj4xvfqUrknT3FPAvFlsmZiECJdFWEMA2M3IgM/1zSGw8lOf5Nb0wu6MzP7AtWA"
                                    "Xm29+k46lJS9axYhiDtTlLuDbE4LEM4ziNO7qyHxl7gwNDiXWyG7DQbAhP3MIqcW"
                                    "1WvlMx8ZZzdo2NtA5ACQ4ZxsH+lu1dUqjS94SqOfCJsXnnUpxqgVwLbe5teZyhCL"
                                    "fMI8lCJaR9iqtzcVATWPDAMBANydhoTu2M3fWb0j93LhMa7JJ6pHHbmXl8H2dbtD"
                                    "kF/Boq27B+iE4AN8amIlmoK01eZNou3FEQKZEsIQ3XxVioTCrILIQWWtqGxskb/3"
                                    "4dQCqvBh768aDCkH5ewpwfZMCbKBiIjeW+n7VDhd2hyGgFaCfgXLqUQbo2lrWjko"
                                    "IhY+iXIirmcc+hgTkl7nXD2zbldnEQvO3jd/ors+oP8z"))
    };
    return testCase;
}

inline TestCase getCaseWithoutOTC() {
    static TestCase testCase{
            .random = FakeRandom(base64decode("dvBgcW5OgsCE5PQWeyY+ew==")),
            .initiatorPublicInfo = VirgilPFSInitiatorPublicInfo(
                    /* identifier */
                    "4c4a1f046c7fba486db78f007c8220b3b9febf3b5f9beb13192f42d4a56e69fd",
                    /* identityPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEA2dxpu/KAjpDN4SUjiju8IjavR8HIPgQlT8s+uYsmP0o=")),
                    /* ephemeralPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEA8NYtIwY9hTSXu95ML0810CeCtYTv5NCtWh3H2Mx3yW8="))),
            .initiatorPrivateInfo = VirgilPFSInitiatorPrivateInfo(
                    /* identifier */
                    "4c4a1f046c7fba486db78f007c8220b3b9febf3b5f9beb13192f42d4a56e69fd",
                    /* identityPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIGD5GI3hfWlVkN3NRRpFakrsYLrc2MKQms447y0yZb2I")),
                    /* ephemeralPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIFKWKLAWp9a7AHKh8+q40FetLqG6gFuWJ9HZn1DLFHoP"))),
            .responderPublicInfo = VirgilPFSResponderPublicInfo(
                    /* identifier */
                    "c1427191d3ad91055e46c08711fe42621c5d2ebd1b459e408bc27204d5137c2a",
                    /* identityPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEABaqQR+SH3qgua/8r7wxDI3mf26IdhVFScW1VayjgQIs=")),
                    /* longTermPublicKey */
                    VirgilPFSPublicKey(base64decode("MCowBQYDK2VwAyEAepJUu3VKTnMwX2y+LjkZ+A8UJLPbLZ5g27gAncROSDQ="))),
            .responderPrivateInfo = VirgilPFSResponderPrivateInfo(
                    /* identifier */
                    "c1427191d3ad91055e46c08711fe42621c5d2ebd1b459e408bc27204d5137c2a",
                    /* identityPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIIGUqUPiUZE0bAhMtrlInLD2M0LlpLf5lANEveWkghCR")),
                    /* longTermPrivateKey */
                    VirgilPFSPrivateKey(
                            base64decode("MC4CAQAwBQYDK2VwBCIEIOr81pHtYGcx0sacPrPmd3Csw2RUceZIS+KYURhtUah4"))),
            .initiatorSession = VirgilPFSSession(
                    /* identifier */
                    base64decode("qaDCsTTzdyPDVw/BEt8jw53KZzDGcm9kllTSjpE8xxc="),
                    /* encryptionSecretKey */
                    base64decode(
                            "rPqLoPidftEqZ4P898B4LENFBdPC49vS9mFSwNeXJhR+rSkR+Tyr3DIhmsnW0gqk2yURmDFPISVyKNU7RHgIvg=="),
                    /* decryptionSecretKey */
                    base64decode(
                            "i5FLjo8blDN+X+MvFbsC6/wqmAfgwAEeuI/LP9d8ng8SZML21c/yFwgWRlSg8/99f0KKv5r4e5ca0cYAFkCcWA=="),
                    /* additionalData */
                    base64decode("IsU1DeVQLext/UxhOQTSIr+kPuKl/1I17cb/3JVhc/Q=")),
            .responderSession = VirgilPFSSession(
                    /* identifier */
                    base64decode("qaDCsTTzdyPDVw/BEt8jw53KZzDGcm9kllTSjpE8xxc="),
                    /* encryptionSecretKey */
                    base64decode(
                            "i5FLjo8blDN+X+MvFbsC6/wqmAfgwAEeuI/LP9d8ng8SZML21c/yFwgWRlSg8/99f0KKv5r4e5ca0cYAFkCcWA=="),
                    /* decryptionSecretKey */
                    base64decode(
                            "rPqLoPidftEqZ4P898B4LENFBdPC49vS9mFSwNeXJhR+rSkR+Tyr3DIhmsnW0gqk2yURmDFPISVyKNU7RHgIvg=="),
                    /* additionalData */
                    base64decode("IsU1DeVQLext/UxhOQTSIr+kPuKl/1I17cb/3JVhc/Q=")),
            .plainText = base64decode(
                    "Rd3bImATu7n/ZKBIFRq9WStMBF6yVXkQLvL1ipsNBGiZnEDNV2PdQoMuhcUEouI/"
                            "W+O7cI84qFxdCZFfmxgFhlKk1roB7j+rKgawsxQ7quPzHO7MnNRPJYbthTDZC8yf"
                            "UtTCSNUUaQL9PwCX/MixCfyoH6d3Thp5+ZggnkSd6LOdHKxnb3HzV9WOgarqNUok"
                            "duU806BiX4JGUQ8JPlHI+JCunNmm+EdUGkGLP9Fy8QbfENHUQpeJppjru/n/6NMp"
                            "sKWsFz7E6y5Maf2551yn6tSpjkp++4c3D9BdfUpXNFprpuB2bzdarP2HY2FhLDaT"
                            "tywWkUEnK6VGbtgfKlGaNxFs5ESBILbu35bClCtVQWG19ef9wfVGerlQQz+32ks1"
                            "HMyvbGBPsHTRAy0O+ieqXKI+TEq5T9fAEDDHfvBmmrBOPra2bFqCWJjFRHIE4H6k"
                            "xmPwwoAsNzHXIfP4ZyG+KgXd74I16QtwCstgpk0DjYmU+RKUq2SDX5qzxDqXONnD"
                            "6DUYL9FtmHAAh4QyI97SULt2M75oNk//nl2gvWHat4mP6d/1ENyjT5u8IySwzhTd"
                            "UNhbxhR27oOVqZcB4vNY6OpldBV1XZl87XmhN02KN1PfejTLT3xh1aoe/bSAwpoQ"
                            "0A2IyTqRkviBy8Q6YVJfmvik07iMdD9K3GrnCySosxSo2OxR88yMwtZcdiPQYHXK"
                            "KmuS/Ao9GVv3J2wrmnON9K9TNdbf0XphJCwJ39NX/AfvrguJs3V4uJN7Pz++KqYJ"
                            "2MCkfjB8DUJwFYhgFpOYPrLQchf+n5WLm1FPoBurctyJSHOTjLNVRfsRH2lmPgD0"
                            "/BUt/EtqsM4LnLq8dIXqujYUTFkXpHdmxxaPZFDTQVSqp6xMSWBATY1ocW0Jkxfu"
                            "4UEvdmriyOeT0exf5Z6rUxplgWYexvly93Geq7M7qYoqGxEbNKo38TxChDGA9wbI"
                            "usn6A7FI87RsQ8GRJNhHK0Nk4r5AVxVI1q6km92AEdkpAqlVXA8+2J6DFbbzRtMh"
                            "B2hp3gWgi1u15t9ZAPd+i2Xd2NlV0US1abTqneTCztaYvu+d/IfUhO7k4BljVZEJ"
                            "Hls1EkT0tZaBz+2wWEjpRx2c3Hxj7UvIr5/4bDTYpqlGvg9SAPfVM4F6BVOA24Jc"
                            "ySyzTi7Qd/zQOUb3dcbTK9RWFUXnpTkuMMAb2oOtkQG/Rjxo1m+7EcniUSu37/Xk"
                            "+4fLYGJaKZtKsqhQ6wFwVJ6uOVM2jiNJ1NrFTA3fgOn1/CGSpmHl9KyP0aIJPwDM"
                            "ig3NORf6utL6AEcIGt6Cq5iQxDSqhifmlcHftZLKom1GavvvpOBAjuI4Z+DNEXDP"
                            "xKbf/IXNZKRtcJ+XDBEAb6Y="),
            .encryptedMessage = VirgilPFSEncryptedMessage(
                    /* sessionIdentifier */
                    base64decode("qaDCsTTzdyPDVw/BEt8jw53KZzDGcm9kllTSjpE8xxc="),
                    /* salt */
                    base64decode("dvBgcW5OgsCE5PQWeyY+ew=="),
                    /* cipherText */
                    base64decode(
                            "czTZc9Mp0CnQSxyigk1uSms7IEp9hK7HtyqoxwaDZ5JuO/ZfZ/oRwax+8jWNqOqJ"
                                    "uPLdpR7HKPZeaqbWdwS53myyU8y6/X+Ir0ylEt+dnRXv9lLW87irL8fOcOX4EPkK"
                                    "8CAIEdOIMJ7qmRnWxy7nfm2j3ZUhadH2YpDRxZ+++67UuDGZe3NQxOE0MjNh833n"
                                    "0bZeMKgl8AAUDEkEMf+ZZ1aL9UyjFgyD13Az7dhyh7Jj+n7xySXWaC/DTUpGjmsG"
                                    "+S6dEYsA7lA4dOLOr9YIqibmZlKISA/OJTRZLD960EtkydHj7vPI9M0oxzaK0RGQ"
                                    "S8q09toVijITQOlxR7vfxJaqqIYF+MYG/fMTeRY0m1u0xUfsRLt7YY/hT2F3Poqb"
                                    "Qzg2D4FbkwgiEB2a1fIEKVWujsKzM9+6vgOw2f5aZgjL6nJW1uGiXU8yeuV7Unx9"
                                    "E2sIB1SljENXucQSEO8x0+YtlwalQltf9PT8qgSi2TvgfhdFjOlnstTX8qaLaGii"
                                    "uZ59SWwPNkSag8xvIbrISf0NixqWGJGWmVSiGeSYXrPN+Xy4BJUCFcOqzMpwsCJF"
                                    "9Ct5jccyImq75IY78auOI5Jffx8gtJg60taQ38R7QBovum4FsjvS09f5zix8fEG4"
                                    "Q2iTX61aJSe5rvIhq53aQEkbpaxMhAh7QsE7V9l5cxETWlasDUrrQIH7eGN3XQ8a"
                                    "r+dKetIIxaW6QZzzwr29QylaUhAYTbV5/f1YSBhex9a8AMhA545BzRTLp+ae6IW9"
                                    "kW6DifdIFYeMVT32MVSnlPxr5XltJMBOhyzqII7UO2vFKmmV0rMsLyPe5H44L6XS"
                                    "Zsue2cAmoVUE7RTIDOLCIUk8AAOByVG+oaeScQhrpunHPGWoK9jRaZM1PE+D/7rM"
                                    "nkpQU8wWel9ZGssljWDrkpyPzCh8bRr0oHRAcbOwLBYCGi9IQvMKh8hucn/3aBpt"
                                    "dS7KJjDXWR+gJub+DdSB/OMkM3W2JvPAXOn/nbswIzOOQUGBIGUE+fJQCy/k+w86"
                                    "95Su8LoHZG6Sq1bNAxxf83UEm4UOoq1dpyyy6EwEpk/sMqpuQo67Tj2QrUMxjc0Q"
                                    "DKGb4Mt+r44IsED9K+Qk3ojfa4L+wHAOTL8jfTs4xbUKH9TzgblKTgj9xxbMCXU+"
                                    "GV6OobF6wJM33PQlbEI8iBkLC3G58pA2EIw+ZkYHZQV6amZIivRmOEUJzqznWRYN"
                                    "u973uMKEw+AlwzMwwas+NA2/ulD6/tDynfXDau6aKM/oMcHqzQoAMHNLxW8U7f8k"
                                    "BdQnC+tZrfJGGhjTaMFs+EwXwKoKD5sLDxX2DTTIVRAxxZ1+ss3BP0sFQHiCspuM"
                                    "51rvNULIbTkBHYLEJPQ7uCNTjvJojjEh8n8WVEvAv+jL"))
    };
    return testCase;
}

}}}}}

#endif //VIRGIL_CRYPTO_PFS_TEST_DATA_PFS_H
