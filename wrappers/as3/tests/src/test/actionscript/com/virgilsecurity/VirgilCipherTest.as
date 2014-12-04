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

    public class VirgilCipherTest {
        private var cipher_:VirgilCipher;

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

        private static const TEST_PLAIN_TEXT : String = "This string will be encrypted.";

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilCipher object and stores it in the 'cipher_' variable.")]
        public function create_cipher() : void {
            cipher_ = VirgilCipher.create();
            assertThat(cipher_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilCipher object stored it in the 'cipher_' variable.")]
        public function destroy_cipher() : void {
            cipher_.destroy();
            cipher_ = null;
        }

        [Test(description="Test VirgilCipher.encrypt() and VirgilCipher.decrypt().")]
        public function test_cipher_encrypt_decrypt():void {
            var plainTextDataSource:VirgilDataSourceWrapper =
                    new VirgilDataSourceWrapper(ConvertionUtils.asciiStringToArray(TEST_PLAIN_TEXT));

            var encryptedText:ByteArray = new ByteArray();
            var encryptedTextDataSink:VirgilDataSinkWrapper = new VirgilDataSinkWrapper(encryptedText);

            var encryptionKey:ByteArray = cipher_.encrypt(plainTextDataSource, encryptedTextDataSink,
                    ConvertionUtils.asciiStringToArray(TEST_PUBLIC_KEY_PEM));

            encryptedText.position = 0;
            var encryptedTextDataSource:VirgilDataSourceWrapper = new VirgilDataSourceWrapper(encryptedText);

            var plainText:ByteArray = new ByteArray();
            var plainTextDataSink:VirgilDataSinkWrapper = new VirgilDataSinkWrapper(plainText);

            cipher_.decrypt(encryptedTextDataSource, plainTextDataSink, encryptionKey,
                    ConvertionUtils.asciiStringToArray(TEST_PRIVATE_KEY_PEM));

            assertThat(ConvertionUtils.arrayToAsciiString(plainText), equalTo(TEST_PLAIN_TEXT));
        }

        [Test(description="Test VirgilCipher.generateKeyPair().")]
        public function test_cipher_generateKeyPair():void {
            var keyPair:VirgilKeyPair = VirgilCipher.generateKeyPair();
            assertThat(keyPair.publicKey().length, not(equalTo(0)));
            assertThat(keyPair.privateKey().length, not(equalTo(0)));
        }

        [Test(description="Test VirgilCipher.generateKeyPair(), VirgilCipher.encrypt(), VirgilCipher.decrypt().")]
        public function test_cipher_encrypt_decrypt_with_generated_keys():void {
            var keyPair:VirgilKeyPair = VirgilCipher.generateKeyPair();

            var plainTextDataSource:VirgilDataSourceWrapper =
                    new VirgilDataSourceWrapper(ConvertionUtils.asciiStringToArray(TEST_PLAIN_TEXT));

            var encryptedText:ByteArray = new ByteArray();
            var encryptedTextDataSink:VirgilDataSinkWrapper = new VirgilDataSinkWrapper(encryptedText);

            var encryptionKey:ByteArray =
                    cipher_.encrypt(plainTextDataSource, encryptedTextDataSink, keyPair.publicKey());

            encryptedText.position = 0;
            var encryptedTextDataSource:VirgilDataSourceWrapper = new VirgilDataSourceWrapper(encryptedText);

            var plainText:ByteArray = new ByteArray();
            var plainTextDataSink:VirgilDataSinkWrapper = new VirgilDataSinkWrapper(plainText);

            cipher_.decrypt(encryptedTextDataSource, plainTextDataSink, encryptionKey, keyPair.privateKey());

            assertThat(ConvertionUtils.arrayToAsciiString(plainText), equalTo(TEST_PLAIN_TEXT));
        }

    }
}
