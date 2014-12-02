package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilSignerTest {
        private var signer_:VirgilSigner;

        private static const TEST_PUBLIC_KEY_PEM : String =
                "-----BEGIN PUBLIC KEY-----\n" +
                "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEa+CTMPBSOFoeZQIPiUOc84r2\n" +
                "BsdPwOzDshzW/JDeY85E8HC+cVF/9K+vdsoeyYP3yGpTwA53hZIKueUh+QAF53C9\n" +
                "X6uaP98Jiu8RMZNplo9p4BZpCwP90A2rxRSatEFHOOtw3FCCmHqzsxpEQCEwnd47\n" +
                "BOP7sd6Nwy37YlX95RM=\n" +
                "-----END PUBLIC KEY-----\n";

        private static const TEST_PRIVATE_KEY_PEM : String =
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MIHaAgEBBEBKFx+SNvhRVb0HpyEBceoVoU4AKZLrx9jdxRdQAS9tC/CQdAmB2t0h\n" +
                "XsMEbtg5DVmwh29GzuLkyTh9VQYxAP/roAsGCSskAwMCCAEBDaGBhQOBggAEa+CT\n" +
                "MPBSOFoeZQIPiUOc84r2BsdPwOzDshzW/JDeY85E8HC+cVF/9K+vdsoeyYP3yGpT\n" +
                "wA53hZIKueUh+QAF53C9X6uaP98Jiu8RMZNplo9p4BZpCwP90A2rxRSatEFHOOtw\n" +
                "3FCCmHqzsxpEQCEwnd47BOP7sd6Nwy37YlX95RM=\n" +
                "-----END EC PRIVATE KEY-----\n";

        private static const TEST_PLAIN_TEXT : String = "This string will be signed.";

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilSigner object and stores it in the 'signer_' variable.")]
        public function create_signer() : void {
            signer_ = VirgilSigner.create();
            assertThat(signer_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilSigner object stored it in the 'signer_' variable.")]
        public function destroy_signer() : void {
            signer_.destroy();
            signer_ = null;
        }

        [Test(description="Test VirgilSigner.sign() and VirgilSigner.verify().")]
        public function test_signer_sign_verify():void {
            var plainTextData:ByteArray = ConvertionUtils.asciiStringToArray(TEST_PLAIN_TEXT);

            var plainTextDataSource:VirgilDataSourceWrapper = new VirgilDataSourceWrapper(plainTextData);

            var signerCertificate:VirgilCertificate =
                    VirgilCertificate.create(ConvertionUtils.asciiStringToArray(TEST_PUBLIC_KEY_PEM));

            var sign:VirgilSign = signer_.sign(plainTextDataSource, signerCertificate,
                    ConvertionUtils.asciiStringToArray(TEST_PRIVATE_KEY_PEM));

            plainTextData.position = 0;
            var verified:Boolean = signer_.verify(plainTextDataSource, sign);
            assertThat(verified, equalTo(true));

            sign.destroy();
            signerCertificate.destroy();
        }

        [Test(description="Test VirgilSigner.signTicket() and VirgilSigner.verifyTicket().")]
        public function test_signer_signTicket_verifyTicket():void {
            var ticket:VirgilUserInfoTicket = VirgilUserInfoTicket.create(
                    ConvertionUtils.asciiStringToArray("Dan"),
                    ConvertionUtils.asciiStringToArray("Doe"),
                    21);

            var signerCertificate:VirgilCertificate =
                    VirgilCertificate.create(ConvertionUtils.asciiStringToArray(TEST_PUBLIC_KEY_PEM));

            var sign:VirgilSign = signer_.signTicket(ticket, signerCertificate,
                    ConvertionUtils.asciiStringToArray(TEST_PRIVATE_KEY_PEM));

            var verified:Boolean = signer_.verifyTicket(ticket, sign);
            assertThat(verified, equalTo(true));

            sign.destroy();
            signerCertificate.destroy();
        }

    }
}
