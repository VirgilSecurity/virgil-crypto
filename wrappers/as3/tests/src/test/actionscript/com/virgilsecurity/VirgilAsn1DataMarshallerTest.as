package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilAsn1DataMarshallerTest {
        private var dataMarshaller_:VirgilDataMarshaller;

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilAsn1DataMarshaller object and stores it in the 'dataMarshaller_' variable.")]
        public function create_dataMarshaller() : void {
            dataMarshaller_ = VirgilAsn1DataMarshaller.create();
            assertThat(dataMarshaller_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilAsn1DataMarshaller object stored it in the 'dataMarshaller_' variable.")]
        public function destroy_dataMarshaller() : void {
            dataMarshaller_.destroy();
            dataMarshaller_ = null;
        }

        [Test(description="Test VirgilAsn1DataMarshaller.marshalAccount(), VirgilAsn1DataMarshaller.demarshalAccount()")]
        public function test_jsonDataMarshaller() : void {
            var account:VirgilAccount = VirgilAccount.create();

            account.id().setAccountId(ConvertionUtils.asciiStringToArray("123"));

            var accountData:ByteArray = dataMarshaller_.marshalAccount(account);
            var restoredAccount:VirgilAccount = dataMarshaller_.demarshalAccount(accountData);

            assertThat(
                ConvertionUtils.arrayToAsciiString(account.id().accountId()), equalTo(
                ConvertionUtils.arrayToAsciiString(restoredAccount.id().accountId()))
            );

            account.destroy();
            restoredAccount.destroy();
        }
    }

}
