package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilUserIdTicketTest {
        private var ticket_:VirgilUserIdTicket;

        private static const TEST_USER_ID:String = "user@domain.com";
        private static const TEST_USER_ID_TYPE:VirgilUserIdType = VirgilUserIdType.email();

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilUserIdTicket object and stores it in the 'ticket_' variable.")]
        public function create_ticket() : void {
            ticket_ = VirgilUserIdTicket.create(ConvertionUtils.asciiStringToArray(TEST_USER_ID), TEST_USER_ID_TYPE);
            assertThat(ticket_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilUserIdTicket object stored it in the 'ticket_' variable.")]
        public function destroy_ticket() : void {
            ticket_.destroy();
            ticket_ = null;
        }

        [Test(description="Test VirgilUserIdTicket::userId().")]
        public function test_ticket_userId():void {
            assertThat(ConvertionUtils.arrayToAsciiString(ticket_.userId()), equalTo(TEST_USER_ID));
        }

        [Test(description="Test VirgilUserIdTicket::userIdType().")]
        public function test_ticket_userIdType():void {
            assertThat(ticket_.userIdType().equals(TEST_USER_ID_TYPE), equalTo(true));
        }

        [Test(description="Test VirgilUserIdTicket::userIdType() returns the same object.")]
        public function test_ticket_userIdType_returns_the_same():void {
            assertThat(ticket_.userIdType().cPtr, ticket_.userIdType().cPtr);
        }

        [Test(description="Test VirgilUserIdTicket::isUserIdTicket().")]
        public function test_ticket_isUserIdTicket():void {
            assertThat(ticket_.isUserIdTicket(), equalTo(true));
        }

        [Test(description="Test VirgilUserIdTicket::isUserInfoTicket().")]
        public function test_ticket_isUserInfoTicket():void {
            assertThat(ticket_.isUserInfoTicket(), equalTo(false));
        }

        [Test(description="Test VirgilUserIdTicket::asUserIdTicket().")]
        public function test_ticket_asUserIdTicket():void {
            assertThat(ticket_.isUserIdTicket(), equalTo(true));
            assertThat(ticket_.asUserIdTicket(), instanceOf(VirgilUserIdTicket));
            assertThat(ticket_, not(strictlyEqualTo(ticket_.asUserIdTicket())));
            assertThat(ticket_.cPtr, equalTo(ticket_.asUserIdTicket().cPtr));
        }

        [Test(description="Test VirgilUserIdTicket::asUserInfoTicket().", expects="Error")]
        public function test_ticket_asUserInfoTicket():void {
            assertThat(ticket_.isUserInfoTicket(), equalTo(false));
            assertThat(ticket_.asUserInfoTicket(), instanceOf(VirgilUserInfoTicket));
        }
    }

}
