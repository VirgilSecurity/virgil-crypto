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

    public class VirgilSignTest {
        private var sign_:VirgilSign;

        private static const TEST_HASH_NAME:String = "SHA512";
        private static const TEST_SIGNED_DIGEST:String = "SIGN DIGEST";
        private static const TEST_SIGNER_CERTIFICATE_ID : String = "CERT-1234";

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilSign object and stores it in the 'sign_' variable.")]
        public function create_sign() : void {
            sign_ = VirgilSign.create(
                    ConvertionUtils.asciiStringToArray(TEST_HASH_NAME),
                    ConvertionUtils.asciiStringToArray(TEST_SIGNED_DIGEST),
                    ConvertionUtils.asciiStringToArray(TEST_SIGNER_CERTIFICATE_ID)
                );
            assertThat(sign_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilSign object stored it in the 'sign_' variable.")]
        public function destroy_sign() : void {
            sign_.destroy();
            sign_ = null;
        }

        [Test(description="Test VirgilSign 'id' accessors.")]
        public function test_sign_id():void {
            assertThat(sign_.id().accountId().length, equalTo(0));
            assertThat(sign_.id().certificateId().length, equalTo(0));
            assertThat(sign_.id().ticketId().length, equalTo(0));
            assertThat(sign_.id().signId().length, equalTo(0));

            var id:VirgilSignId = VirgilSignId.create();
            id.setAccountId(ConvertionUtils.asciiStringToArray("123"));
            id.setCertificateId(ConvertionUtils.asciiStringToArray("456"));
            id.setTicketId(ConvertionUtils.asciiStringToArray("789"));
            id.setSignId(ConvertionUtils.asciiStringToArray("000"));
            sign_.setId(id);
            id.destroy();

            assertThat(sign_.id().accountId().length, not(equalTo(0)));
            assertThat(sign_.id().certificateId().length, not(equalTo(0)));
            assertThat(sign_.id().ticketId().length, not(equalTo(0)));
            assertThat(sign_.id().signId().length, not(equalTo(0)));

            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().accountId()), equalTo("123"));
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().certificateId()), equalTo("456"));
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().ticketId()), equalTo("789"));
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().signId()), equalTo("000"));
        }

        [Test(description="Test VirgilSignId 'id' accessor is mutable")]
        public function test_sign_id_mutable():void {
            assertThat(sign_.id().accountId().length, equalTo(0));
            assertThat(sign_.id().certificateId().length, equalTo(0));
            assertThat(sign_.id().ticketId().length, equalTo(0));
            assertThat(sign_.id().signId().length, equalTo(0));

            sign_.id().setAccountId(ConvertionUtils.asciiStringToArray("123"));
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().accountId()), equalTo("123"));

            sign_.id().setCertificateId(ConvertionUtils.asciiStringToArray("456"));
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().certificateId()), equalTo("456"));

            sign_.id().setTicketId(ConvertionUtils.asciiStringToArray("789"));
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().ticketId()), equalTo("789"));

            sign_.id().setSignId(ConvertionUtils.asciiStringToArray("000"));
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.id().signId()), equalTo("000"));
        }

        [Test(description="Test VirgilSign::hashName().")]
        public function test_sign_hashName():void {
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.hashName()), equalTo(TEST_HASH_NAME));
        }

        [Test(description="Test VirgilSign::signedDigest().")]
        public function test_sign_signedDigest():void {
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.signedDigest()), equalTo(TEST_SIGNED_DIGEST));
        }

        [Test(description="Test VirgilSign::signerCertificateId().")]
        public function test_sign_signerCertificateId():void {
            assertThat(ConvertionUtils.arrayToAsciiString(sign_.signerCertificateId()),
                    equalTo(TEST_SIGNER_CERTIFICATE_ID));
        }
    }

}
