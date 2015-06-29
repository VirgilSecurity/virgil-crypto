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

package com.virgilsecurity.crypto.base {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.utils.*;
    import com.virgilsecurity.extension.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilHashTest {
        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Test(description="VirgilHash.md5()")]
        public function test_md5():void {
            var hash:VirgilHash = VirgilHash.md5();
            internal_hash(hash, "", "d41d8cd98f00b204e9800998ecf8427e");
            internal_hash(hash, "abc", "900150983cd24fb0d6963f7d28e17f72");
            internal_hash(hash, "Test Строка", "041e9cea31ca2db024d1ca35f5459821");
            internal_hash_hmac(hash, "", "", "74e6f7298a9c2d168935f58c001bad88");
            internal_hash_hmac(hash, "key", "", "63530468a04e386459855da0063b6596");
            internal_hash_hmac(hash, "", "abc", "dd2701993d29fdd0b032c233cec63403");
            internal_hash_hmac(hash, "Ключ", "Test Строка", "2e6b2b70fa31cfec8fbb367a1c847424");
            hash.destroy();
        }

        [Test(description="VirgilHash.sha256()")]
        public function test_sha256():void {
            var hash:VirgilHash = VirgilHash.sha256();
            internal_hash(hash, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            internal_hash(hash, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            internal_hash(hash, "Test Строка", "42c75cfbbc6768ccf3e6ae282f590f81633ccfae74d2eaef027d4bf134fb6e66");
            internal_hash_hmac(hash, "", "", "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
            internal_hash_hmac(hash, "key", "", "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
            internal_hash_hmac(hash, "", "abc", "fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351");
            internal_hash_hmac(hash, "Ключ", "Test Строка",
                    "06a5047051fbbafe37bb263a5d3075544f0dc5736a1acaaaf3219f41c0865cb6");
            hash.destroy();
        }

        [Test(description="VirgilHash.sha384()")]
        public function test_sha384():void {
            var hash:VirgilHash = VirgilHash.sha384();
            internal_hash(hash, "",
                    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743" +
                    "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
            internal_hash(hash, "abc",
                    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163" +
                    "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
            internal_hash(hash, "Test Строка",
                    "a8efc47270ab051597e1e074a348652b64a823fa844c943a" +
                    "063815bdb9880ff9512837c5b66c9195573eb5d9afbebbfc");
            internal_hash_hmac(hash, "", "",
                    "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114" +
                    "b3d4367776d14d3551289e75e8209cd4b792302840234adc");
            internal_hash_hmac(hash, "key", "",
                    "99f44bb4e73c9d0ef26533596c8d8a32a5f8c10a9b997d30" +
                    "d89a7e35ba1ccf200b985f72431202b891fe350da410e43f");
            internal_hash_hmac(hash, "", "abc",
                    "948f7c5caa500c31d7d4a0f52f3e3da7e33c8a9fe6ef528b" +
                    "8a9ac3e4adc4e24d908e6f40b737510e82354759dc5e9f06");
            internal_hash_hmac(hash, "Ключ", "Test Строка",
                    "745b1c97714edc4f786f1ce792c0970428ab625bee010c8d" +
                    "553e1691eb198d0a438d65a1cd6c7a433d3b75e49627ac38");
            hash.destroy();
        }

        [Test(description="VirgilHash.sha512()")]
        public function test_sha512():void {
            var hash:VirgilHash = VirgilHash.sha512();
            internal_hash(hash, "",
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
            internal_hash(hash, "abc",
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
            internal_hash(hash, "Test Строка",
                    "3c7c478c27f7ef13bd8ee59fc97bc7e90cb6ca166d622c9c1816a88301adcf05" +
                    "ca1f2f897d73c7e8ce6d744853f115209db6bad7829ee864f0fdfcba1ca482c5");
            internal_hash_hmac(hash, "", "",
                    "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac673" +
                    "0c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47");
            internal_hash_hmac(hash, "key", "",
                    "84fa5aa0279bbc473267d05a53ea03310a987cecc4c1535ff29b6d76b8f1444a" +
                    "728df3aadb89d4a9a6709e1998f373566e8f824a8ca93b1821f0b69bc2a2f65e");
            internal_hash_hmac(hash, "", "abc",
                    "29689f6b79a8dd686068c2eeae97fd8769ad3ba65cb5381f838358a8045a358e" +
                    "e3ba1739c689c7805e31734fb6072f87261d1256995370d55725cba00d10bdd0");
            internal_hash_hmac(hash, "Ключ", "Test Строка",
                    "ca78a023cb14e4e31e25f6f891a59e562225b7a4ca4de6cd6f8d614926a5bdbc" +
                    "f77b7a634424f9c4f12bf4f44e9c42aaaa168a2550499746ba9d25a0a7128dbe");
            hash.destroy();
        }

        [Test(description="VirgilHash.withName()")]
        public function test_withName_md5():void {
            var hash:VirgilHash = VirgilHash.withName(ConvertionUtils.utf8StringToArray("md5"));
            internal_hash(hash, "", "d41d8cd98f00b204e9800998ecf8427e");
            internal_hash(hash, "abc", "900150983cd24fb0d6963f7d28e17f72");
            internal_hash(hash, "Test Строка", "041e9cea31ca2db024d1ca35f5459821");
            internal_hash_hmac(hash, "", "", "74e6f7298a9c2d168935f58c001bad88");
            internal_hash_hmac(hash, "key", "", "63530468a04e386459855da0063b6596");
            internal_hash_hmac(hash, "", "abc", "dd2701993d29fdd0b032c233cec63403");
            internal_hash_hmac(hash, "Ключ", "Test Строка", "2e6b2b70fa31cfec8fbb367a1c847424");
            hash.destroy();
        }

        private function internal_hash(hash:VirgilHash, dataString:String, expectedDigestHex:String):void {
            var digest:ByteArray = null;
            var data:ByteArray = ConvertionUtils.utf8StringToArray(dataString);
            // Immediate Hashing
            digest = hash.hash(data);
            assertThat(Hex.fromArray(digest), equalTo(expectedDigestHex));

            // Chunk hashing
            var dataChunk:ByteArray = new ByteArray();
            const chunkSize:uint = 2;
            data.position = 0;
            hash.start();
            while(data.bytesAvailable > 0) {
                dataChunk.clear();
                data.readBytes(dataChunk, 0, Math.min(chunkSize, data.bytesAvailable));
                hash.update(dataChunk);
            }
            digest = hash.finish();
            assertThat(Hex.fromArray(digest), equalTo(expectedDigestHex));
        }

        private function internal_hash_hmac(hash:VirgilHash, keyString:String, dataString:String,
                expectedHmacDigestHex:String):void {
            var hmacDigest:ByteArray = null;
            var key:ByteArray = ConvertionUtils.utf8StringToArray(keyString);
            var data:ByteArray = ConvertionUtils.utf8StringToArray(dataString);
            // Immediate HMAC
            hmacDigest = hash.hmac(key, data);
            assertThat(Hex.fromArray(hmacDigest), equalTo(expectedHmacDigestHex));

            // Chunk HMAC
            var dataChunk:ByteArray = new ByteArray();
            const chunkSize:uint = 2;
            data.position = 0;
            hash.hmacStart(key);
            while(data.bytesAvailable > 0) {
                dataChunk.clear();
                data.readBytes(dataChunk, 0, Math.min(chunkSize, data.bytesAvailable));
                hash.hmacUpdate(dataChunk);
            }
            hmacDigest = hash.hmacFinish();
            assertThat(Hex.fromArray(hmacDigest), equalTo(expectedHmacDigestHex));

            // Chunk HMAC (after reset)
            data.position = 0;
            hash.hmacReset();
            while(data.bytesAvailable > 0) {
                dataChunk.clear();
                data.readBytes(dataChunk, 0, Math.min(chunkSize, data.bytesAvailable));
                hash.hmacUpdate(dataChunk);
            }
            hmacDigest = hash.hmacFinish();
            assertThat(Hex.fromArray(hmacDigest), equalTo(expectedHmacDigestHex));
        }
    }
}
