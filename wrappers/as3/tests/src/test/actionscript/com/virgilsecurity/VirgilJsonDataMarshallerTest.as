package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilJsonDataMarshallerTest {
        private var dataMarshaller_:VirgilDataMarshaller;

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilJsonDataMarshaller object and stores it in the 'dataMarshaller_' variable.")]
        public function create_dataMarshaller() : void {
            dataMarshaller_ = VirgilJsonDataMarshaller.create();
            assertThat(dataMarshaller_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilJsonDataMarshaller object stored it in the 'dataMarshaller_' variable.")]
        public function destroy_dataMarshaller() : void {
            dataMarshaller_.destroy();
            dataMarshaller_ = null;
        }

        [Test(description="Test VirgilJsonDataMarshaller.marshalAccount(), VirgilJsonDataMarshaller.demarshalAccount()")]
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
