/**
 * Copyright (C) 2014 Virgil Security Inc.
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

package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilCertificateTest {
        private static var TEST_ACCOUNT_ID : int = 123;
        private static var TEST_ACCOUNT_ID_REVERSE : int = 321;
        private static var TEST_CERTIFICATE_ID : int = 456;
        private static var TEST_CERTIFICATE_ID_REVERSE : int = 654;
        private static var TEST_PUBLIC_KEY_PEM : String =
                "-----BEGIN PUBLIC KEY-----\n" +
                "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEa+CTMPBSOFoeZQIPiUOc84r2\n" +
                "BsdPwOzDshzW/JDeY85E8HC+cVF/9K+vdsoeyYP3yGpTwA53hZIKueUh+QAF53C9\n" +
                "X6uaP98Jiu8RMZNplo9p4BZpCwP90A2rxRSatEFHOOtw3FCCmHqzsxpEQCEwnd47\n" +
                "BOP7sd6Nwy37YlX95RM=\n" +
                "-----END PUBLIC KEY-----\n";

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Test(description="VirgilCertificate")]
        public function test_certificate() : void {

            var certificateId:VirgilCertificateId = VirgilCertificateId.create();
            assertThat(certificateId.cPtr, not(equalTo(0)));

            var accountIdData:ByteArray = new ByteArray();
            accountIdData.writeInt(TEST_ACCOUNT_ID);
            certificateId.setAccountId(accountIdData);

            var certificateIdData:ByteArray = new ByteArray();
            certificateIdData.writeInt(TEST_CERTIFICATE_ID);
            certificateId.setCertificateId(certificateIdData);

            assertThat(certificateId.accountId().readInt(), equalTo(TEST_ACCOUNT_ID));
            assertThat(certificateId.certificateId().readInt(), equalTo(TEST_CERTIFICATE_ID));

            var publicKeyData:ByteArray = ConvertionUtils.utfStringToArray(TEST_PUBLIC_KEY_PEM);
            var certificate:VirgilCertificate = VirgilCertificate.create(publicKeyData);

            var publicKeyDataExtracted:ByteArray = certificate.publicKey();
            assertThat(publicKeyData.position, equalTo(publicKeyDataExtracted.position));
            assertThat(publicKeyData.length, equalTo(publicKeyDataExtracted.length));

            assertThat(certificate.cPtr, not(equalTo(0)));
            assertThat(ConvertionUtils.arrayToUTFString(publicKeyDataExtracted), TEST_PUBLIC_KEY_PEM);
            assertThat(certificate.id().accountId().length, equalTo(0));
            assertThat(certificate.id().certificateId().length, equalTo(0));

            certificate.setId(certificateId);
            assertThat(certificate.id().accountId().readInt(), equalTo(TEST_ACCOUNT_ID));
            assertThat(certificate.id().certificateId().readInt(), equalTo(TEST_CERTIFICATE_ID));

            var accountIdReverseData:ByteArray = new ByteArray();
            accountIdReverseData.writeInt(TEST_ACCOUNT_ID_REVERSE);
            certificate.id().setAccountId(accountIdReverseData);
            assertThat(certificate.id().accountId().readInt(), equalTo(TEST_ACCOUNT_ID_REVERSE));
            assertThat(certificateId.accountId().readInt(), not(equalTo(TEST_ACCOUNT_ID_REVERSE)));

            var certificateIdReverseData:ByteArray = new ByteArray();
            certificateIdReverseData.writeInt(TEST_CERTIFICATE_ID_REVERSE);
            certificate.id().setCertificateId(certificateIdReverseData);
            assertThat(certificate.id().certificateId().readInt(), equalTo(TEST_CERTIFICATE_ID_REVERSE));
            assertThat(certificateId.certificateId().readInt(), not(equalTo(TEST_CERTIFICATE_ID_REVERSE)));

            certificateId.destroy();
            certificate.destroy();
        }
    }

}
