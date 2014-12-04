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
