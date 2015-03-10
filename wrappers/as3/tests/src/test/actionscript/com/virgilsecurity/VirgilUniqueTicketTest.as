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

    public class VirgilUniqueTicketTest {
        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        private function check_ticket(type:VirgilUniqueTicketType, value:String):void {
            var ticket:VirgilUniqueTicket = VirgilUniqueTicket.create(type,
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

        private function check_ticket_marshalling_asn1(ticket:VirgilUniqueTicket):void {
            var asn1:ByteArray = ticket.toAsn1();
            var restoredTicket:VirgilUniqueTicket = VirgilUniqueTicket.createDefault();
            restoredTicket.fromAsn1(asn1);
            assertThat(restoredTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        private function check_ticket_marshalling_json(ticket:VirgilUniqueTicket):void {
            var json:ByteArray = ticket.toJson();
            var restoredTicket:VirgilUniqueTicket = VirgilUniqueTicket.createDefault();
            restoredTicket.fromJson(json);
            assertThat(restoredTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        private function check_ticket_marshalling_asn1_thru_base_class(ticket:VirgilUniqueTicket):void {
            var asn1:ByteArray = ticket.toAsn1();
            var restoredTicket:VirgilTicket = VirgilTicket.createFromAsn1(asn1);
            assertThat(restoredTicket.isUniqueTicket(), equalTo(true));
            var restoredUniqueTicket:VirgilUniqueTicket = restoredTicket.asUniqueTicket();
            assertThat(restoredUniqueTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredUniqueTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        private function check_ticket_marshalling_json_thru_base_class(ticket:VirgilUniqueTicket):void {
            var json:ByteArray = ticket.toAsn1();
            var restoredTicket:VirgilTicket = VirgilTicket.createFromJson(json);
            assertThat(restoredTicket.isUniqueTicket(), equalTo(true));
            var restoredUniqueTicket:VirgilUniqueTicket = restoredTicket.asUniqueTicket();
            assertThat(restoredUniqueTicket.type(), equalTo(ticket.type()));
            assertThat(ConvertionUtils.arrayToAsciiString(restoredUniqueTicket.value()),
                    equalTo(ConvertionUtils.arrayToAsciiString(ticket.value())));
            restoredTicket.destroy();
        }

        [Test(description="Test VirgilUniqueTicket of type VirgilUniqueTicketType.Email.")]
        public function test_type_Email():void {
            check_ticket(VirgilUniqueTicketType.Email, "test@test.com");
        }

        [Test(description="Test VirgilUniqueTicket of type VirgilUniqueTicketType.Phone.")]
        public function test_type_Phone():void {
            check_ticket(VirgilUniqueTicketType.Phone, "+1 777 777 7777");
        }

        [Test(description="Test VirgilUniqueTicket of type VirgilUniqueTicketType.Fax.")]
        public function test_type_Fax():void {
            check_ticket(VirgilUniqueTicketType.Fax, "+1 999 999 9999");
        }

        [Test(description="Test VirgilUniqueTicket of type VirgilUniqueTicketType.Domain.")]
        public function test_type_Domain():void {
            check_ticket(VirgilUniqueTicketType.Domain, "domain.test.com");
        }

        [Test(description="Test VirgilUniqueTicket of type VirgilUniqueTicketType.MacAddress.")]
        public function test_type_MacAddress():void {
            check_ticket(VirgilUniqueTicketType.MacAddress, "AA:BB:CC:DD:EE:FF");
        }

        [Test(description="Test VirgilUniqueTicket of type VirgilUniqueTicketType.Application.")]
        public function test_type_Application():void {
            check_ticket(VirgilUniqueTicketType.Application, "com.reverse.dns.app");
        }
    }
}
