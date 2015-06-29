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

import com.virgilsecurity.wrapper.*;
import com.virgilsecurity.extension.*;
import com.virgilsecurity.crypto.foundation.*;

public class VirgilVersion {
    public static function asString():String {
        return _wrap_VirgilVersion_asString();
    }
    public static function asNumber():uint {
        return _wrap_VirgilVersion_asNumber();
    }
    public static function majorVersion():uint {
        return _wrap_VirgilVersion_majorVersion();
    }
    public static function minorVersion():uint {
        return _wrap_VirgilVersion_minorVersion();
    }
    public static function patchVersion():uint {
        return _wrap_VirgilVersion_patchVersion();
    }
}

public class VirgilRandom extends CObject {
    public static function create(personalInfo:ByteArray):VirgilRandom {
        var obj = new VirgilRandom();
        obj.cPtr = _wrap_new_VirgilRandom(personalInfo);
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilRandom(this.cPtr);
    }
    public function randomize(bytesNum:uint):ByteArray {
        return _wrap_VirgilRandom_randomize(this.cPtr, bytesNum);
    }
}

public class VirgilKeyPair extends CObject {
    public static function create(publicKey:ByteArray, privateKey:ByteArray):VirgilKeyPair {
        var obj = new VirgilKeyPair();
        obj.cPtr = _wrap_new_VirgilKeyPair_init(publicKey, privateKey);
        return obj;
    }
    public static function generate(password:ByteArray = null):VirgilKeyPair {
        var obj = new VirgilKeyPair();
        obj.cPtr = _wrap_new_VirgilKeyPair_generate(password);
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilKeyPair(this.cPtr);
    }
    public function publicKey():ByteArray {
        return _wrap_VirgilKeyPair_publicKey(this.cPtr);
    }
    public function privateKey():ByteArray {
        return _wrap_VirgilKeyPair_privateKey(this.cPtr);
    }
}

public class VirgilCustomParams extends CObject {
    public function isEmpty():Boolean {
        return _wrap_VirgilCustomParameters_isEmpty(this.cPtr);
    }
    public function clear():void {
        return _wrap_VirgilCustomParameters_clear(this.cPtr);
    }
    public function setInteger(key:ByteArray, value:int):void {
        _wrap_VirgilCustomParameters_setInteger(this.cPtr, key, value);
    }
    public function getInteger(key:ByteArray):int {
        return _wrap_VirgilCustomParameters_getInteger(this.cPtr, key);
    }
    public function removeInteger(key:ByteArray):void {
        _wrap_VirgilCustomParameters_removeInteger(this.cPtr, key);
    }
    public function setString(key:ByteArray, value:ByteArray):void {
        _wrap_VirgilCustomParameters_setString(this.cPtr, key, value);
    }
    public function getString(key:ByteArray):ByteArray {
        return _wrap_VirgilCustomParameters_getString(this.cPtr, key);
    }
    public function removeString(key:ByteArray):void {
        _wrap_VirgilCustomParameters_removeString(this.cPtr, key);
    }
    public function setData(key:ByteArray, value:ByteArray):void {
        _wrap_VirgilCustomParameters_setData(this.cPtr, key, value);
    }
    public function getData(key:ByteArray):ByteArray {
        return _wrap_VirgilCustomParameters_getData(this.cPtr, key);
    }
    public function removeData(key:ByteArray):void {
        _wrap_VirgilCustomParameters_removeData(this.cPtr, key);
    }
}

public class VirgilCipherBase extends CObject {
    public function addKeyRecipient(recipientId:ByteArray, publicKey:ByteArray):void {
        _wrap_VirgilCipherBase_addKeyRecipient(this.cPtr, recipientId, publicKey);
    }
    public function removeKeyRecipient(recipientId:ByteArray):void {
        _wrap_VirgilCipherBase_removeKeyRecipient(this.cPtr, recipientId);
    }
    public function addPasswordRecipient(password:ByteArray):void {
        _wrap_VirgilCipherBase_addPasswordRecipient(this.cPtr, password);
    }
    public function removePasswordRecipient(password:ByteArray):void {
        _wrap_VirgilCipherBase_removePasswordRecipient(this.cPtr, password);
    }
    public function removeAllRecipients():void {
        _wrap_VirgilCipherBase_removeAllRecipients(this.cPtr);
    }
    public function getContentInfo():ByteArray {
        return _wrap_VirgilCipherBase_getContentInfo(this.cPtr);
    }
    public function setContentInfo(contentInfo:ByteArray):void {
        _wrap_VirgilCipherBase_setContentInfo(this.cPtr, contentInfo);
    }
    public function customParams():VirgilCustomParams {
        var customParams:VirgilCustomParams = new VirgilCustomParams();
        customParams.cPtr = _wrap_VirgilCipherBase_customParams(this.cPtr);
        return customParams;
    }
}

public class VirgilCipher extends VirgilCipherBase {
    public static function create():VirgilCipher {
        var obj = new VirgilCipher();
        obj.cPtr = _wrap_new_VirgilCipher();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilCipher(this.cPtr);
    }
    public function encrypt(data:ByteArray, embedContentInfo:Boolean = false):ByteArray {
        return _wrap_VirgilCipher_encrypt(this.cPtr, data, embedContentInfo);
    }
    public function decryptWithKey(encryptedData:ByteArray, recipientId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):ByteArray {
        return _wrap_VirgilCipher_decryptWithKey(this.cPtr, encryptedData, recipientId,
                privateKey, privateKeyPassword);
    }
    public function decryptWithPassword(encryptedData:ByteArray, password:ByteArray):ByteArray {
        return _wrap_VirgilCipher_decryptWithPassword(this.cPtr, encryptedData, password);
    }
}

public class VirgilStreamCipher extends VirgilCipherBase {
    public static function create():VirgilStreamCipher {
        var obj = new VirgilStreamCipher();
        obj.cPtr = _wrap_new_VirgilStreamCipher();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilStreamCipher(this.cPtr);
    }
    public function encrypt(dataSource:IVirgilDataSource, dataSink:IVirgilDataSink,
            embedContentInfo:Boolean = false):void {
        _wrap_VirgilStreamCipher_encrypt(this.cPtr, dataSource, dataSink, embedContentInfo);
    }
    public function decryptWithKey(dataSource:IVirgilDataSource, dataSink:IVirgilDataSink, recipientId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):void {
        _wrap_VirgilStreamCipher_decryptWithKey(
                cPtr, dataSource, dataSink, recipientId, privateKey, privateKeyPassword);
    }
    public function decryptWithPassword(dataSource:IVirgilDataSource, dataSink:IVirgilDataSink,
                password:ByteArray):void {
        _wrap_VirgilStreamCipher_decryptWithPassword(this.cPtr, dataSource, dataSink, password);
    }
}

public class VirgilChunkCipher extends VirgilCipherBase {
    public static function create():VirgilChunkCipher {
        var obj = new VirgilChunkCipher();
        obj.cPtr = _wrap_new_VirgilChunkCipher();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilChunkCipher(this.cPtr);
    }
    public function startEncryption(preferredChunkSize:uint):uint {
        return _wrap_VirgilChunkCipher_startEncryption(this.cPtr, preferredChunkSize);
    }
    public function startDecryptionWithKey(recipientId:ByteArray, privateKey:ByteArray,
                privateKeyPassword:ByteArray = null):uint {
        return _wrap_VirgilChunkCipher_startDecryptionWithKey(this.cPtr, recipientId,
                privateKey, privateKeyPassword);
    }
    public function startDecryptionWithPassword(password:ByteArray):uint {
        return _wrap_VirgilChunkCipher_startDecryptionWithKey(this.cPtr, password);
    }
    public function process(data:ByteArray):ByteArray {
        return _wrap_VirgilChunkCipher_process(this.cPtr, data);
    }
    public function finish():void {
        return _wrap_VirgilChunkCipher_finish(this.cPtr);
    }
}

public class VirgilSigner extends CObject {
    public static function create():VirgilSigner {
        var obj = new VirgilSigner();
        obj.cPtr = _wrap_new_VirgilSigner();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilSigner(this.cPtr);
    }
    public function sign(data:ByteArray, privateKey:ByteArray, privateKeyPassword:ByteArray = null):ByteArray {
        return _wrap_VirgilSigner_sign(this.cPtr, data, privateKey, privateKeyPassword);
    }
    public function verify(data:ByteArray, sign:ByteArray, publicKey:ByteArray):Boolean {
        return _wrap_VirgilSigner_verify(this.cPtr, data, sign, publicKey);
    }
}

public class VirgilStreamSigner extends CObject {
    public static function create():VirgilStreamSigner {
        var obj = new VirgilStreamSigner();
        obj.cPtr = _wrap_new_VirgilStreamSigner();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilStreamSigner(this.cPtr);
    }
    public function sign(dataSource:IVirgilDataSource, privateKey:ByteArray,
            privateKeyPassword:ByteArray = null):ByteArray {
        return _wrap_VirgilStreamSigner_sign(this.cPtr, dataSource, privateKey, privateKeyPassword);
    }
    public function verify(dataSource:IVirgilDataSource, sign:ByteArray, publicKey:ByteArray):Boolean {
        return _wrap_VirgilStreamSigner_verify(this.cPtr, dataSource, sign, publicKey);
    }
}

}
