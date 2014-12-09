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

    public class VirgilChunkCipherTest {
        private var cipher_:VirgilChunkCipher;

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

        private static const TEST_PASSWORD : String = "password";

        private static const TEST_PLAIN_TEXT : String = "This very long string will be encrypted.";

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilChunkCipher object and stores it in the 'cipher_' variable.")]
        public function create_cipher() : void {
            cipher_ = VirgilChunkCipher.create();
            assertThat(cipher_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilChunkCipher object stored it in the 'cipher_' variable.")]
        public function destroy_cipher() : void {
            cipher_.destroy();
            cipher_ = null;
        }

        [Test(description="Test VirgilChunkCipher main functionality.")]
        public function test_cipher():void {
            var dataChunk:ByteArray = new ByteArray();
            const encryptionChunkSize:uint = cipher_.adjustEncryptionChunkSize(5);

            // Encrypt
            var encryptionKey:ByteArray = cipher_.startEncryption(
                    ConvertionUtils.asciiStringToArray(TEST_PUBLIC_KEY_PEM));

            var encryptedData:ByteArray = new ByteArray();
            var plainData:ByteArray = ConvertionUtils.asciiStringToArray(TEST_PLAIN_TEXT);
            while (plainData.bytesAvailable > 0) {
                dataChunk.clear();
                plainData.readBytes(dataChunk, 0, Math.min(encryptionChunkSize, plainData.bytesAvailable));
                encryptedData.writeBytes(cipher_.process(dataChunk));
            }
            cipher_.finalize();

            // Decrypt
            const decryptionChunkSize:uint = cipher_.adjustDecryptionChunkSize(encryptionChunkSize);
            cipher_.startDecryption(encryptionKey, ConvertionUtils.asciiStringToArray(TEST_PRIVATE_KEY_PEM));
            var decryptedData:ByteArray = new ByteArray();
            encryptedData.position = 0;
            while (encryptedData.bytesAvailable > 0) {
                dataChunk.clear();
                encryptedData.readBytes(dataChunk, 0, Math.min(decryptionChunkSize, encryptedData.bytesAvailable));
                decryptedData.writeBytes(cipher_.process(dataChunk));
            }
            cipher_.finalize();

            // Check results
            assertThat(ConvertionUtils.arrayToAsciiString(decryptedData), equalTo(TEST_PLAIN_TEXT));
        }

    }
}
