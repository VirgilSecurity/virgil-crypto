/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

(function() {
    function virgil_init () {
      Module['VirgilByteArray']['fromUTF8'] = function(string) {
          var ba = new Module.VirgilByteArray();
          ba.fromUTF8(string);
          return ba;
      };

      Module['VirgilByteArray']['prototype']['fromUTF8'] = function(string) {
          var s = unescape(encodeURIComponent(string));
          var charList = s.split('');
          var uintArray = [];
          for (var i = 0; i < charList.length; ++i) {
              uintArray.push(charList[i].charCodeAt(0));
          }
          this.assign(new Uint8Array(uintArray));
      };

      Module['VirgilByteArray']['prototype']['toUTF8'] = function() {
          var encodedString = String.fromCharCode.apply(null, this.data());
          return decodeURIComponent(escape(encodedString));
      };

      Module['VirgilByteArray']['fromUint8Array'] = function(uint8Array) {
          var byteArray = new Module.VirgilByteArray;
          byteArray.assign(uint8Array);
          return byteArray;
      };

      Module['VirgilByteArray']['prototype']['fromUint8Array'] = function(uint8Array) {
          this.assign(uint8Array);
      };

      Module['VirgilByteArray']['prototype']['toUint8Array'] = function() {
          var size = this.size();
          var array = new Uint8Array(size);
          for (var i = 0; i < size; ++i) {
              array[i] = this.get(i);
          }
          return array;
      };

      Module['VirgilStreamDataSource'] = Module.VirgilDataSource.extend("VirgilDataSource", {
          __construct: function(uint8Array, chunkSize) {
              this.__parent.__construct.call(this);
              this.position = 0;
              this.chunkSize = chunkSize || 1024 * 1024; // 1MB by default
              this.bytes = uint8Array;
          },
          hasData: function() {
              return this.position < this.bytes.length;
          },
          read: function() {
              var start = this.position;
              var end = start + this.chunkSize;
              var chunk = this._slice(start, end);
              var bytesRead = chunk.length;
              var byteArray = Module.VirgilByteArray.fromUint8Array(chunk);

              this.seek(this.position + bytesRead);
              return byteArray;
          },
          seek: function(offset) {
              if (offset < 0) {
                  offset = this.bytes.length + offset;
              }
              this.position = offset;
          },
          _slice: function(start, end) {
              if (typeof this.bytes.slice === 'function') {
                  return this.bytes.slice(start, end);
              }
              var source = this.bytes;
              var len = source.length;
              var relativeStart = start;
              var k = (relativeStart < 0) ? Math.max(len + relativeStart, 0) : Math.min(relativeStart, len);
              var relativeEnd = (end === undefined) ? len : end;
              var final = (relativeEnd < 0) ? Math.max(len + relativeEnd, 0) : Math.min(relativeEnd, len);
              var count = final - k;
              var dest = new Uint8Array(count);
              var n = 0;
              while (k < final) {
                  dest[n] = source[k];
                  ++k;
                  ++n;
              }
              return dest;
          }
      });

      Module['VirgilStreamDataSink'] = Module.VirgilDataSink.extend("VirgilDataSink", {
          __construct: function() {
              this.__parent.__construct.call(this);
              this.bytes = new Uint8Array(0);
          },
          isGood: function() {
              return true;
          },
          write: function(bytes) {
              var chunk = bytes.toUint8Array();
              this._append(chunk);
          },
          getBytes: function () {
              return this.bytes;
          },
          _append: function (uint8Array) {
              var result;
              var totalLength = this.bytes.length + uint8Array.length;

              result = new Uint8Array(totalLength);
              result.set(this.bytes, 0);
              result.set(uint8Array, this.bytes.length);

              this.bytes = result;
          }
      });

      Module['VirgilKeyPair']['Type'] = Module['VirgilKeyPairType']
      Module['VirgilPBKDF']['Algorithm'] = Module['VirgilPBKDFAlgorithm']
      Module['VirgilHash']['Algorithm'] = Module['VirgilHashAlgorithm']
      Module['VirgilTinyCipher']['PackageSize'] = Module['VirgilTinyCipherPackageSize']
      Module['VirgilHash']['Algorithm'] = Module['VirgilHashAlgorithm']
      Module['VirgilPBE']['Algorithm'] = Module['VirgilPBEAlgorithm']
      Module['VirgilSymmetricCipher']['Algorithm'] = Module['VirgilSymmetricCipherAlgorithm']
      Module['VirgilSymmetricCipher']['Padding'] = Module['VirgilSymmetricCipherPadding']
    }

    var originalOnInit = Module['onRuntimeInitialized'];
    Module['onRuntimeInitialized'] = function onRuntimeInitialized() {
      virgil_init();
      if (typeof originalOnInit === 'function') {
        originalOnInit();
      }
    };
})();
