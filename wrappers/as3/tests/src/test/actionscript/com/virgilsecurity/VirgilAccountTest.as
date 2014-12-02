package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilAccountTest {
        private static var TEST_ACCOUNT_ID : int = 12345;
        private static var TEST_ACCOUNT_ID_REVERSE : int = 54321;

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Test(description="VirgilAccount")]
        public function test_account() : void {
            var accountId:VirgilAccountId = VirgilAccountId.create();
            assertThat(accountId.cPtr, not(equalTo(0)));

            var accountIdData:ByteArray = new ByteArray();
            accountIdData.writeInt(TEST_ACCOUNT_ID);
            accountId.setAccountId(accountIdData);

            assertThat(accountId.accountId().readInt(), equalTo(TEST_ACCOUNT_ID));

            var account:VirgilAccount = VirgilAccount.create();
            assertThat(account.cPtr, not(equalTo(0)));
            assertThat(account.id().accountId().length, equalTo(0));

            account.setId(accountId);
            assertThat(account.id().accountId().readInt(), equalTo(TEST_ACCOUNT_ID));

            var accountIdReverseData:ByteArray = new ByteArray();
            accountIdReverseData.writeInt(TEST_ACCOUNT_ID_REVERSE);
            account.id().setAccountId(accountIdReverseData);
            assertThat(account.id().accountId().readInt(), equalTo(TEST_ACCOUNT_ID_REVERSE));
            assertThat(accountId.accountId().readInt(), not(equalTo(TEST_ACCOUNT_ID_REVERSE)));

            accountId.destroy();
            account.destroy();
        }
    }

}
