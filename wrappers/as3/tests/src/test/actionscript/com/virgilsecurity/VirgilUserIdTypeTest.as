package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilUserIdTypeTest {
        private var ticket_:VirgilUserIdType;

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Test(description="Test VirgilUserIdType::email().")]
        public function test_user_id_type_email():void {
            assertThat(VirgilUserIdType.email().isEmail(), equalTo(true));
            assertThat(VirgilUserIdType.email().code(), equalTo(0));
            assertThat(VirgilUserIdType.email().name(), equalTo("email"));
        }

        [Test(description="Test VirgilUserIdType::phone().")]
        public function test_user_id_type_phone():void {
            assertThat(VirgilUserIdType.phone().isPhone(), equalTo(true));
            assertThat(VirgilUserIdType.phone().code(), equalTo(1));
            assertThat(VirgilUserIdType.phone().name(), equalTo("phone"));
        }

        [Test(description="Test VirgilUserIdType::fax().")]
        public function test_user_id_type_fax():void {
            assertThat(VirgilUserIdType.fax().isFax(), equalTo(true));
            assertThat(VirgilUserIdType.fax().code(), equalTo(2));
            assertThat(VirgilUserIdType.fax().name(), equalTo("fax"));
        }
    }

}
