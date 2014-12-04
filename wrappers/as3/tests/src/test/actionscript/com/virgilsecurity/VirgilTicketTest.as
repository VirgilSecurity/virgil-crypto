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

    public class VirgilTicketTest {
        private var ticket_:VirgilTicket;

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilTicket object and stores it in the 'ticket_' variable.")]
        public function create_ticket() : void {
            ticket_ = VirgilTicket.create();
            assertThat(ticket_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilTicket object stored it in the 'ticket_' variable.")]
        public function destroy_ticket() : void {
            ticket_.destroy();
            ticket_ = null;
        }

        [Test(description="Test VirgilTicket 'id' accessors.")]
        public function test_ticket_id():void {
            assertThat(ticket_.id().accountId().length, equalTo(0));
            assertThat(ticket_.id().certificateId().length, equalTo(0));
            assertThat(ticket_.id().ticketId().length, equalTo(0));

            var id:VirgilTicketId = VirgilTicketId.create();
            id.setAccountId(ConvertionUtils.asciiStringToArray("123"));
            id.setCertificateId(ConvertionUtils.asciiStringToArray("456"));
            id.setTicketId(ConvertionUtils.asciiStringToArray("789"));
            ticket_.setId(id);
            id.destroy();

            assertThat(ticket_.id().accountId().length, not(equalTo(0)));
            assertThat(ticket_.id().certificateId().length, not(equalTo(0)));
            assertThat(ticket_.id().ticketId().length, not(equalTo(0)));

            assertThat(ConvertionUtils.arrayToAsciiString(ticket_.id().accountId()), equalTo("123"));
            assertThat(ConvertionUtils.arrayToAsciiString(ticket_.id().certificateId()), equalTo("456"));
            assertThat(ConvertionUtils.arrayToAsciiString(ticket_.id().ticketId()), equalTo("789"));
        }

        [Test(description="Test VirgilTicketId 'id' accessor is mutable")]
        public function test_ticket_id_mutable():void {
            assertThat(ticket_.id().accountId().length, equalTo(0));
            assertThat(ticket_.id().certificateId().length, equalTo(0));
            assertThat(ticket_.id().ticketId().length, equalTo(0));

            ticket_.id().setAccountId(ConvertionUtils.asciiStringToArray("123"));
            assertThat(ConvertionUtils.arrayToAsciiString(ticket_.id().accountId()), equalTo("123"));

            ticket_.id().setCertificateId(ConvertionUtils.asciiStringToArray("456"));
            assertThat(ConvertionUtils.arrayToAsciiString(ticket_.id().certificateId()), equalTo("456"));

            ticket_.id().setTicketId(ConvertionUtils.asciiStringToArray("789"));
            assertThat(ConvertionUtils.arrayToAsciiString(ticket_.id().ticketId()), equalTo("789"));
        }

        [Test(description="Test VirgilTicket::isUserIdTicket().")]
        public function test_ticket_isUserIdTicket():void {
            assertThat(ticket_.isUserIdTicket(), equalTo(false));
        }

        [Test(description="Test VirgilTicket::isUserInfoTicket().")]
        public function test_ticket_isUserInfoTicket():void {
            assertThat(ticket_.isUserInfoTicket(), equalTo(false));
        }

    }

}
