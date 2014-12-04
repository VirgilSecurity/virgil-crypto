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

    public class ConvertionUtils {

        static public function asciiStringToArray(string : String) : ByteArray {
            var result : ByteArray = new ByteArray ();
            result.writeMultiByte(string, "iso-8859-1");
            result.position = 0;
            return result;
        }

        static public function arrayToAsciiString(array : ByteArray) : String {
            var pos : int = array.position;
            array.position = 0;
            try {
                var result : String = array.readMultiByte(array.length, "iso-8859-1");
            } finally {
                array.position = pos;
            }
            return  result;
        }

        static public function utfStringToArray(string : String) : ByteArray {
            var result : ByteArray = new ByteArray ();
            result.writeUTFBytes(string);
            result.position = 0;
            return result;
        }

        static public function arrayToUTFString(array : ByteArray) : String {
            var pos : int = array.position;
            array.position = 0;
            try {
                var result : String = array.readUTFBytes(array.length);
            } finally {
                array.position = pos;
            }
            return result;;
        }
    }
}
