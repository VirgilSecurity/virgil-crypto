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
    import com.virgilsecurity.extension.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilInfoTicketTest {
        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        private function check_ticket(type:VirgilInfoTicketType, value:String):void {
            var ticket:VirgilInfoTicket = VirgilInfoTicket.create(type,
                    ConvertionUtils.asciiStringToArray(value)
                );
            assertThat(ticket.cPtr, not(equalTo(0)));
            assertThat(ticket.type(), equalTo(type));
            assertThat(ConvertionUtils.arrayToAsciiString(ticket.value()), equalTo(value));
            check_ticket_marshalling_asn1(ticket);
            check_ticket_marshalling_json(ticket);
            check_ticket_marshalling_asn1_thru_base_class(ticket);
            check_ticket_marshalling_json_thru_base_class(ticket);
            ticket.destroy();
        }

        private function check_ticket_marshalling_asn1(ticket:VirgilInfoTicket):void {
            var asn1:ByteArray = ticket.toAsn1();
            var restoredTicket:VirgilInfoTicket = VirgilInfoTicket.createDefault();
            restoredTicket.fromAsn1(asn1);
            assertThat(restoredTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        private function check_ticket_marshalling_json(ticket:VirgilInfoTicket):void {
            var json:ByteArray = ticket.toJson();
            var restoredTicket:VirgilInfoTicket = VirgilInfoTicket.createDefault();
            restoredTicket.fromJson(json);
            assertThat(restoredTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        private function check_ticket_marshalling_asn1_thru_base_class(ticket:VirgilInfoTicket):void {
            var asn1:ByteArray = ticket.toAsn1();
            var restoredTicket:VirgilTicket = VirgilTicket.createFromAsn1(asn1);
            assertThat(restoredTicket.isInfoTicket(), equalTo(true));
            var restoredInfoTicket:VirgilInfoTicket = restoredTicket.asInfoTicket();
            assertThat(restoredInfoTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredInfoTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        private function check_ticket_marshalling_json_thru_base_class(ticket:VirgilInfoTicket):void {
            var json:ByteArray = ticket.toAsn1();
            var restoredTicket:VirgilTicket = VirgilTicket.createFromJson(json);
            assertThat(restoredTicket.isInfoTicket(), equalTo(true));
            var restoredInfoTicket:VirgilInfoTicket = restoredTicket.asInfoTicket();
            assertThat(restoredInfoTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredInfoTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        [Test(description="Test VirgilInfoTicket of type VirgilInfoTicketType.FirstName.")]
        public function test_type_FirstName():void {
            check_ticket(VirgilInfoTicketType.FirstName, "Dan");
        }

        [Test(description="Test VirgilInfoTicket of type VirgilInfoTicketType.LastName.")]
        public function test_type_LastName():void {
            check_ticket(VirgilInfoTicketType.LastName, "Doe");
        }

        [Test(description="Test VirgilInfoTicket of type VirgilInfoTicketType.MiddleName.")]
        public function test_type_MiddleName():void {
            check_ticket(VirgilInfoTicketType.MiddleName, "David");
        }

        [Test(description="Test VirgilInfoTicket of type VirgilInfoTicketType.Nickname.")]
        public function test_type_Nickname():void {
            check_ticket(VirgilInfoTicketType.Nickname, "superman");
        }

        [Test(description="Test VirgilInfoTicket of type VirgilInfoTicketType.BirthDate.")]
        public function test_type_BirthDate():void {
            check_ticket(VirgilInfoTicketType.BirthDate, "01/01/2000");
        }
    }
}
