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
