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

import C_Run.*;
import com.adobe.flascc.swig.*;
import flash.utils.ByteArray;
import flash.utils.IDataInput;
import flash.utils.IDataOutput;

import com.virgilsecurity.wrapper.*;
import com.virgilsecurity.extension.*;

public class VirgilVersion {
    public static function asString():String {
        return _wrap_VirgilVersion_asString();
    }
    public static function asHexNumber():uint {
        return _wrap_VirgilVersion_asHexNumber();
    }
    public static function majorNumber():uint {
        return _wrap_VirgilVersion_majorNumber();
    }
    public static function minorNumber():uint {
        return _wrap_VirgilVersion_minorNumber();
    }
    public static function patchNumber():uint {
        return _wrap_VirgilVersion_patchNumber();
    }
}

public class VirgilSerializable extends CObject implements IVirgilAsn1Compatible, IVirgilJsonCompatible {
    public function toAsn1():ByteArray {
        return _wrap_VirgilSerializable_toAsn1(this.cPtr);
    }
    public function fromAsn1(asn1:ByteArray):void {
        _wrap_VirgilSerializable_fromAsn1(this.cPtr, asn1);
    }
    public function toJson():ByteArray {
        return _wrap_VirgilSerializable_toJson(this.cPtr);
    }
    public function fromJson(json:ByteArray):void {
        _wrap_VirgilSerializable_fromJson(this.cPtr, json);
    }
}

public class VirgilId extends VirgilSerializable {
    public function isEmpty():Boolean {
        return _wrap_VirgilId_isEmpty(this.cPtr);
    }
    public function clear():void {
        _wrap_VirgilId_clear(this.cPtr);
    }
}

public class VirgilAccountId extends VirgilId {
    public static function create():VirgilAccountId {
        var obj = new VirgilAccountId();
        obj.cPtr = _wrap_new_VirgilAccountId();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilAccountId(this.cPtr);
    }
    public function accountId():ByteArray {
        return _wrap_VirgilAccountId_accountId(this.cPtr);
    }
    public function setAccountId(accountId:ByteArray):void {
        _wrap_VirgilAccountId_setAccountId(this.cPtr, accountId);
    }
}

public class VirgilCertificateId extends VirgilAccountId {
    public static function create():VirgilCertificateId {
        var obj = new VirgilCertificateId();
        obj.cPtr = _wrap_new_VirgilCertificateId();
        return obj;
    }
    public function certificateId():ByteArray {
        return _wrap_VirgilCertificateId_certificateId(this.cPtr);
    }
    public function setCertificateId(certificateId:ByteArray):void {
        _wrap_VirgilCertificateId_setCertificateId(this.cPtr, certificateId);
    }
}

public class VirgilTicketId extends VirgilCertificateId {
    public static function create():VirgilTicketId {
        var obj = new VirgilTicketId();
        obj.cPtr = _wrap_new_VirgilTicketId();
        return obj;
    }
    public function ticketId():ByteArray {
        return _wrap_VirgilTicketId_ticketId(this.cPtr);
    }
    public function setTicketId(ticketId:ByteArray):void {
        _wrap_VirgilTicketId_setTicketId(this.cPtr, ticketId);
    }
}

public class VirgilSignId extends VirgilTicketId {
    public static function create():VirgilSignId {
        var obj = new VirgilSignId();
        obj.cPtr = _wrap_new_VirgilSignId();
        return obj;
    }
    public function signId():ByteArray {
        return _wrap_VirgilSignId_signId(this.cPtr);
    }
    public function setSignId(signId:ByteArray):void {
        _wrap_VirgilSignId_setSignId(this.cPtr, signId);
    }
}

public class VirgilAccount extends VirgilSerializable {
    public static function create():VirgilAccount {
        var obj = new VirgilAccount();
        obj.cPtr = _wrap_new_VirgilAccount();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilAccount(this.cPtr);
    }
    public function id():VirgilAccountId {
        var accountId:VirgilAccountId = new VirgilAccountId();
        accountId.cPtr = _wrap_VirgilAccount_id(this.cPtr);
        return accountId;
    }
    public function setId(accountId:VirgilAccountId):void {
        _wrap_VirgilAccount_setId(this.cPtr, accountId.cPtr);
    }
}

public class VirgilCertificate extends VirgilSerializable {
    public static function create(publicKey:ByteArray):VirgilCertificate {
        var obj = new VirgilCertificate();
        obj.cPtr = _wrap_new_VirgilCertificate_init(publicKey);
        return obj;
    }
    public static function createDefault():VirgilCertificate {
        var obj = new VirgilCertificate();
        obj.cPtr = _wrap_new_VirgilCertificate(publicKey);
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilCertificate(this.cPtr);
    }
    public function id():VirgilCertificateId {
        var certificateId:VirgilCertificateId = new VirgilCertificateId();
        certificateId.cPtr = _wrap_VirgilCertificate_id(this.cPtr);
        return certificateId;
    }
    public function setId(certificateId:VirgilCertificateId):void {
        _wrap_VirgilCertificate_setId(this.cPtr, certificateId.cPtr);
    }
    public function publicKey():ByteArray {
        return _wrap_VirgilCertificate_publicKey(this.cPtr);
    }
}

public class VirgilTicket extends VirgilSerializable {
    public static function createFromAsn1(asn1:ByteArray):VirgilTicket {
        var ticket:VirgilTicket = new VirgilTicket();
        ticket.cPtr = _wrap_VirgilTicket_createFromAsn1(asn1);
        return ticket;
    }
    public static function createFromJson(json:ByteArray):VirgilTicket {
        var ticket:VirgilTicket = new VirgilTicket();
        ticket.cPtr = _wrap_VirgilTicket_createFromJson(json);
        return ticket;
    }
    public function destroy():void {
        _wrap_delete_VirgilTicket(this.cPtr);
    }
    public function id():VirgilTicketId {
        var ticketId:VirgilTicketId = new VirgilTicketId();
        ticketId.cPtr = _wrap_VirgilTicket_id(this.cPtr);
        return ticketId;
    }
    public function setId(ticketId:VirgilTicketId):void {
        _wrap_VirgilTicket_setId(this.cPtr, ticketId.cPtr);
    }
    public function isUniqueTicket():Boolean {
        return _wrap_VirgilTicket_isUniqueTicket(this.cPtr);
    }
    public function asUniqueTicket():VirgilUniqueTicket {
        var uniqueTicket:VirgilUniqueTicket = new VirgilUniqueTicket();
        uniqueTicket.cPtr = _wrap_VirgilTicket_asUniqueTicket(this.cPtr);
        return uniqueTicket;
    }
    public function isInfoTicket():Boolean {
        return _wrap_VirgilTicket_isInfoTicket(this.cPtr);
    }
    public function asInfoTicket():VirgilInfoTicket {
        var infoTicket:VirgilInfoTicket = new VirgilInfoTicket();
        infoTicket.cPtr = _wrap_VirgilTicket_asInfoTicket(this.cPtr);
        return infoTicket;
    }
}

public class VirgilUniqueTicket extends VirgilTicket {
    public static function create(type:VirgilUniqueTicketType, value:ByteArray):VirgilUniqueTicket {
        var obj = new VirgilUniqueTicket();
        obj.cPtr = _wrap_new_VirgilUniqueTicket_init(type.code, value);
        return obj;
    }
    public static function createDefault():VirgilUniqueTicket {
        var obj = new VirgilUniqueTicket();
        obj.cPtr = _wrap_new_VirgilUniqueTicket();
        return obj;
    }
    public function type():VirgilUniqueTicketType {
        return VirgilUniqueTicketType.fromCode(_wrap_VirgilUniqueTicket_type(this.cPtr));
    }

    public function value():ByteArray {
        return _wrap_VirgilUniqueTicket_value(this.cPtr);
    }
}

public class VirgilInfoTicket extends VirgilTicket {
    public static function create(type:VirgilInfoTicketType, value:ByteArray):VirgilInfoTicket {
        var obj = new VirgilInfoTicket();
        obj.cPtr = _wrap_new_VirgilInfoTicket_init(type.code, value);
        return obj;
    }
    public static function createDefault():VirgilInfoTicket {
        var obj = new VirgilInfoTicket();
        obj.cPtr = _wrap_new_VirgilInfoTicket();
        return obj;
    }
    public function type():VirgilInfoTicketType {
        return VirgilInfoTicketType.fromCode(_wrap_VirgilInfoTicket_type(this.cPtr));
    }
    public function value():ByteArray {
        return _wrap_VirgilInfoTicket_value(this.cPtr);
    }
}

public class VirgilSign extends VirgilSerializable {
    public static function create(hashName:ByteArray, signedDigest:ByteArray,
            signerCertificateId:ByteArray):VirgilSign {
        var obj = new VirgilSign();
        obj.cPtr = _wrap_new_VirgilSign_init(hashName, signedDigest, signerCertificateId);
        return obj;
    }
    public static function createDefault():VirgilSign {
        var obj = new VirgilSign();
        obj.cPtr = _wrap_new_VirgilSign();
        return obj;
    }
    public function destroy():void {
        _wrap_delete_VirgilSign(this.cPtr);
    }
    public function id():VirgilSignId {
        var signId:VirgilSignId = new VirgilSignId();
        signId.cPtr = _wrap_VirgilSign_id(this.cPtr);
        return signId;
    }
    public function setId(signId:VirgilSignId):void {
        _wrap_VirgilSign_setId(this.cPtr, signId.cPtr);
    }
    public function hashName():ByteArray {
        return _wrap_VirgilSign_hashName(this.cPtr);
    }
    public function signedDigest():ByteArray {
        return _wrap_VirgilSign_signedDigest(this.cPtr);
    }
    public function signerCertificateId():ByteArray {
        return _wrap_VirgilSign_signerCertificateId(this.cPtr);
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

public class VirgilContentInfo {
    public static function defineSize(contentInfo:ByteArray):uint {
        return _wrap_VirgilContentInfo_defineSize(contentInfo);
    }
}

public class VirgilCipherBase extends CObject {
    public function addKeyRecipient(certificateId:ByteArray, publicKey:ByteArray):void {
        _wrap_VirgilCipherBase_addKeyRecipient(this.cPtr, certificateId, publicKey);
    }
    public function removeKeyRecipient(certificateId:ByteArray):void {
        _wrap_VirgilCipherBase_removeKeyRecipient(this.cPtr, certificateId);
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
    public function decryptWithKey(encryptedData:ByteArray, certificateId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):ByteArray {
        return _wrap_VirgilCipher_decryptWithKey(this.cPtr, encryptedData, certificateId,
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
    public function decryptWithKey(dataSource:IVirgilDataSource, dataSink:IVirgilDataSink, certificateId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):void {
        _wrap_VirgilStreamCipher_decryptWithKey(
                cPtr, dataSource, dataSink, certificateId, privateKey, privateKeyPassword);
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
    public function startDecryptionWithKey(certificateId:ByteArray, privateKey:ByteArray,
                privateKeyPassword:ByteArray = null):uint {
        return _wrap_VirgilChunkCipher_startDecryptionWithKey(this.cPtr, certificateId,
                privateKey, privateKeyPassword);
    }
    public function startDecryptionWithPassword(password:ByteArray):uint {
        return _wrap_VirgilChunkCipher_startDecryptionWithKey(this.cPtr, password);
    }
    public function process(data:ByteArray):ByteArray {
        return _wrap_VirgilChunkCipher_process(this.cPtr, data);
    }
    public function finalize():void {
        return _wrap_VirgilChunkCipher_finalize(this.cPtr);
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
    public function sign(data:ByteArray, signerCertificateId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):VirgilSign {
        var sign:VirgilSign = new VirgilSign();
        sign.cPtr = _wrap_VirgilSigner_sign(this.cPtr, data, signerCertificateId, privateKey, privateKeyPassword);
        return sign;
    }
    public function verify(data:ByteArray, sign:VirgilSign, publicKey:ByteArray):Boolean {
        return _wrap_VirgilSigner_verify(this.cPtr, data, sign.cPtr, publicKey);
    }
    public function signObject(obj:IVirgilAsn1Compatible, signerCertificateId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):VirgilSign {
        var sign:VirgilSign = new VirgilSign();
        sign.cPtr = _wrap_VirgilSigner_signObject(
                cPtr, obj.cPtr, signerCertificateId, privateKey, privateKeyPassword);
        return sign;
    }
    public function verifyObject(obj:IVirgilAsn1Compatible, sign:VirgilSign, publicKey:ByteArray):Boolean {
        return _wrap_VirgilSigner_verifyObject(this.cPtr, obj.cPtr, sign.cPtr, publicKey);
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
    public function sign(dataSource:IVirgilDataSource, signerCertificateId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):VirgilSign {
        var sign:VirgilSign = new VirgilSign();
        sign.cPtr = _wrap_VirgilStreamSigner_sign(this.cPtr, dataSource, signerCertificateId, privateKey,
                privateKeyPassword);
        return sign;
    }
    public function verify(dataSource:IVirgilDataSource, sign:VirgilSign, publicKey:ByteArray):Boolean {
        return _wrap_VirgilStreamSigner_verify(this.cPtr, dataSource, sign.cPtr, publicKey);
    }
}

}
