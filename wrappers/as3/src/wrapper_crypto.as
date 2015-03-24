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

package com.virgilsecurity.crypto {

import C_Run.*;
import com.adobe.flascc.swig.*;
import flash.utils.ByteArray;
import flash.utils.IDataInput;
import flash.utils.IDataOutput;

import com.virgilsecurity.extension.*;

public class VirgilHash extends CObject implements IVirgilAsn1Compatible {
    public static function create():VirgilHash {
        var obj = new VirgilHash();
        obj.cPtr = _wrap_new_VirgilHash();
        return obj;
    }
    public static function md5():VirgilHash {
        var obj = new VirgilHash();
        obj.cPtr = _wrap_VirgilHash_md5();
        return obj;
    }
    public static function sha256():VirgilHash {
        var obj = new VirgilHash();
        obj.cPtr = _wrap_VirgilHash_sha256();
        return obj;
    }
    public static function sha384():VirgilHash {
        var obj = new VirgilHash();
        obj.cPtr = _wrap_VirgilHash_sha384();
        return obj;
    }
    public static function sha512():VirgilHash {
        var obj = new VirgilHash();
        obj.cPtr = _wrap_VirgilHash_sha512();
        return obj;
    }
    public static function withName(name:ByteArray):VirgilHash {
        var obj = new VirgilHash();
        obj.cPtr = _wrap_VirgilHash_withName(name);
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilHash(this.cPtr);
    }
    public function toAsn1():ByteArray {
        return _wrap_VirgilSerializable_toAsn1(this.cPtr);
    }
    public function fromAsn1(asn1:ByteArray):void {
        _wrap_VirgilSerializable_fromAsn1(this.cPtr, asn1);
    }
    public function name():String {
        return _wrap_VirgilHash_name(this.cPtr);
    }
    public function hash(data:ByteArray):ByteArray {
        return _wrap_VirgilHash_hash(this.cPtr, data);
    }
    public function start():void {
        _wrap_VirgilHash_start(this.cPtr);
    }
    public function update(data:ByteArray):void {
        _wrap_VirgilHash_update(this.cPtr, data);
    }
    public function finish():ByteArray {
        return _wrap_VirgilHash_finish(this.cPtr);
    }
    public function hmac(key:ByteArray, data:ByteArray):ByteArray {
        return _wrap_VirgilHash_hmac(this.cPtr, key, data);
    }
    public function hmacStart(key:ByteArray):void {
        _wrap_VirgilHash_hmacStart(this.cPtr, key);
    }
    public function hmacReset():void {
        _wrap_VirgilHash_hmacReset(this.cPtr);
    }
    public function hmacUpdate(data:ByteArray):void {
        _wrap_VirgilHash_hmacUpdate(this.cPtr, data);
    }
    public function hmacFinish():ByteArray {
        return _wrap_VirgilHash_hmacFinish(this.cPtr);
    }
}

}
