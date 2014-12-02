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
