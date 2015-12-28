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

    public class VirgilKeyPairTest {
        private static const TEST_PUBLIC_KEY_PEM : String =
                "-----BEGIN PUBLIC KEY-----\n" +
                "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEa+CTMPBSOFoeZQIPiUOc84r2\n" +
                "BsdPwOzDshzW/JDeY85E8HC+cVF/9K+vdsoeyYP3yGpTwA53hZIKueUh+QAF53C9\n" +
                "X6uaP98Jiu8RMZNplo9p4BZpCwP90A2rxRSatEFHOOtw3FCCmHqzsxpEQCEwnd47\n" +
                "BOP7sd6Nwy37YlX95RM=\n" +
                "-----END PUBLIC KEY-----\n";

        private static const TEST_PRIVATE_KEY_PEM : String =
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MIHaAgEBBEBKFx+SNvhRVb0HpyEBceoVoU4AKZLrx9jdxRdQAS9tC/CQdAmB2t0h\n" +
                "XsMEbtg5DVmwh29GzuLkyTh9VQYxAP/roAsGCSskAwMCCAEBDaGBhQOBggAEa+CT\n" +
                "MPBSOFoeZQIPiUOc84r2BsdPwOzDshzW/JDeY85E8HC+cVF/9K+vdsoeyYP3yGpT\n" +
                "wA53hZIKueUh+QAF53C9X6uaP98Jiu8RMZNplo9p4BZpCwP90A2rxRSatEFHOOtw\n" +
                "3FCCmHqzsxpEQCEwnd47BOP7sd6Nwy37YlX95RM=\n" +
                "-----END EC PRIVATE KEY-----\n";

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Test(description="Test create VirgilKeyPair with known keys.")]
        public function test_keypair_create():void {
            var keyPair:VirgilKeyPair = VirgilKeyPair.create(
                    ConvertionUtils.asciiStringToArray(TEST_PUBLIC_KEY_PEM),
                    ConvertionUtils.asciiStringToArray(TEST_PRIVATE_KEY_PEM)
                );
            assertThat(keyPair.cPtr, not(equalTo(0)));
            assertThat(ConvertionUtils.arrayToAsciiString(keyPair.publicKey()), equalTo(TEST_PUBLIC_KEY_PEM));
            assertThat(ConvertionUtils.arrayToAsciiString(keyPair.privateKey()), equalTo(TEST_PRIVATE_KEY_PEM));
            keyPair.destroy();
        }

        [Test(description="Test generate VirgilKeyPair.")]
        public function test_keypair_generate():void {
            var keyPair:VirgilKeyPair = VirgilKeyPair.generate();
            assertThat(keyPair.cPtr, not(equalTo(0)));
            assertThat(keyPair.publicKey().length, not(equalTo(0)));
            assertThat(keyPair.privateKey().length, not(equalTo(0)));
            keyPair.destroy();
        }

        [Test(description="Test generate VirgilKeyPair with password.")]
        public function test_keypair_generate_with_password():void {
            var keyPair:VirgilKeyPair = VirgilKeyPair.generate(
                    ConvertionUtils.asciiStringToArray("password"));
            assertThat(keyPair.cPtr, not(equalTo(0)));
            assertThat(keyPair.publicKey().length, not(equalTo(0)));
            assertThat(keyPair.privateKey().length, not(equalTo(0)));
            keyPair.destroy();
        }

        [Test(description="Test KeyPair validation.")]
        public function test_keypair_validation():void {
            var keyPair1:VirgilKeyPair = VirgilKeyPair.generate(
                    ConvertionUtils.asciiStringToArray("password"));
            var keyPair2:VirgilKeyPair = VirgilKeyPair.generate();


            assertThat(VirgilKeyPair.isKeyPairMatch(keyPair1.publicKey(), keyPair1.privateKey()), equalTo(true));
            assertThat(VirgilKeyPair.isKeyPairMatch(keyPair2.publicKey(), keyPair1.privateKey()), equalTo(false));

            assertThat(VirgilKeyPair.checkPrivateKeyPassword(keyPair2.privateKey(),
                    ConvertionUtils.asciiStringToArray("password")), equalTo(true));
            assertThat(VirgilKeyPair.checkPrivateKeyPassword(keyPair2.privateKey(),
                    ConvertionUtils.asciiStringToArray("wrong_password")), equalTo(false));

            assertThat(VirgilKeyPair.isPrivateKeyEncrypted(keyPair1.privateKey()), equalTo(false));
            assertThat(VirgilKeyPair.isPrivateKeyEncrypted(keyPair2.privateKey()), equalTo(true));

            keyPair1.destroy();
            keyPair2.destroy();
        }
    }
}
