/**
 * Copyright (C) 2015 Virgil Security Inc.
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

package com.virgilsecurity.crypto {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.utils.*;
    import com.virgilsecurity.extension.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilByteArrayUtilsTest {
        private static const PRETTY_JSON_STRING : String =
            "{" +
            "    \"object\" : {" +
            "        \"number_integer\" : 123," +
            "        \"bool_true\" : true," +
            "        \"bool_false\" : false," +
            "        \"string\" : \"test string\"" +
            "    }," +
            "    \"array\" : [" +
            "        1, true, false, \"test string\"" +
            "    ]," +
            "    \"bool_true\" : true," +
            "    \"null\" : null," +
            "    \"bool_false\" : false," +
            "    \"number_integer\" : 123," +
            "    \"string\" : \"test_string\"" +
            "}";

        private static const REARRANGED_JSON_STRING : String =
            "{" +
            "    \"bool_false\" : false," +
            "    \"null\" : null," +
            "    \"number_integer\" : 123," +
            "    \"array\" : [" +
            "        1, true, false, \"test string\"" +
            "    ]," +
            "    \"string\" : \"test_string\"," +
            "    \"bool_true\" : true," +
            "    \"object\" : {" +
            "        \"bool_false\" : false," +
            "        \"string\" : \"test string\"," +
            "        \"bool_true\" : true," +
            "        \"number_integer\" : 123" +
            "    }" +
            "}";

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Test(description="Test 'jsonToBytes' convertion")]
        public function test_json_to_bytes():void {
            var prettyJsonBytes:ByteArray = VirgilByteArrayUtils.jsonToBytes(PRETTY_JSON_STRING);
            var rearrangedJsonBytes:ByteArray = VirgilByteArrayUtils.jsonToBytes(REARRANGED_JSON_STRING);
            assertThat(VirgilByteArrayUtils.bytesToHex(prettyJsonBytes),
                    equalTo(VirgilByteArrayUtils.bytesToHex(rearrangedJsonBytes)));
        }
    }
}
