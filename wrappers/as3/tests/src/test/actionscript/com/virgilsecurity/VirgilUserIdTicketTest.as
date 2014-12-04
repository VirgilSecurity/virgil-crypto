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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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
