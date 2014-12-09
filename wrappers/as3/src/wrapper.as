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

public class VirgilRandom {
    public var cPtr:int;

    public static function create(personalInfo:ByteArray):VirgilRandom {
        var obj = new VirgilRandom();
        obj.cPtr = _wrap_new_VirgilRandom(personalInfo);
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilRandom(cPtr);
    }

    public function randomize(bytesNum:uint):ByteArray {
        return _wrap_VirgilRandom_randomize(cPtr, bytesNum);
    }
}

public class VirgilAccountId {
    public var cPtr:int;

    public static function create():VirgilAccountId {
        var obj = new VirgilAccountId();
        obj.cPtr = _wrap_new_VirgilAccountId();
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilAccountId(cPtr);
    }

    public function accountId():ByteArray {
        return _wrap_VirgilAccountId_accountId(cPtr);
    }

    public function setAccountId(accountId:ByteArray):void {
        _wrap_VirgilAccountId_setAccountId(cPtr, accountId);
    }
}

public class VirgilCertificateId extends VirgilAccountId {
    public static function create():VirgilCertificateId {
        var obj = new VirgilCertificateId();
        obj.cPtr = _wrap_new_VirgilCertificateId();
        return obj;
    }

    override public function destroy():void {
        _wrap_delete_VirgilCertificateId(cPtr);
    }

    public function certificateId():ByteArray {
        return _wrap_VirgilCertificateId_certificateId(cPtr);
    }

    public function setCertificateId(certificateId:ByteArray):void {
        _wrap_VirgilCertificateId_setCertificateId(cPtr, certificateId);
    }
}

public class VirgilTicketId extends VirgilCertificateId {
    public static function create():VirgilTicketId {
        var obj = new VirgilTicketId();
        obj.cPtr = _wrap_new_VirgilTicketId();
        return obj;
    }

    override public function destroy():void {
        _wrap_delete_VirgilTicketId(cPtr);
    }

    public function ticketId():ByteArray {
        return _wrap_VirgilTicketId_ticketId(cPtr);
    }

    public function setTicketId(ticketId:ByteArray):void {
        _wrap_VirgilTicketId_setTicketId(cPtr, ticketId);
    }
}

public class VirgilSignId extends VirgilTicketId {
    public static function create():VirgilSignId {
        var obj = new VirgilSignId();
        obj.cPtr = _wrap_new_VirgilSignId();
        return obj;
    }

    override public function destroy():void {
        _wrap_delete_VirgilSignId(cPtr);
    }

    public function signId():ByteArray {
        return _wrap_VirgilSignId_signId(cPtr);
    }

    public function setSignId(signId:ByteArray):void {
        _wrap_VirgilSignId_setSignId(cPtr, signId);
    }
}

public class VirgilAccount {
    public var cPtr:int;

    public static function create():VirgilAccount {
        var obj = new VirgilAccount();
        obj.cPtr = _wrap_new_VirgilAccount();
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilAccount(cPtr);
    }

    public function id():VirgilAccountId {
        var accountId:VirgilAccountId = new VirgilAccountId();
        accountId.cPtr = _wrap_VirgilAccount_id(cPtr);
        return accountId;
    }

    public function setId(accountId:VirgilAccountId):void {
        _wrap_VirgilAccount_setId(cPtr, accountId.cPtr);
    }
}

public class VirgilCertificate {
    public var cPtr:int;

    public static function create(publicKey:ByteArray):VirgilCertificate {
        var obj = new VirgilCertificate();
        obj.cPtr = _wrap_new_VirgilCertificate(publicKey);
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilCertificate(cPtr);
    }

    public function id():VirgilCertificateId {
        var certificateId:VirgilCertificateId = new VirgilCertificateId();
        certificateId.cPtr = _wrap_VirgilCertificate_id(cPtr);
        return certificateId;
    }

    public function setId(certificateId:VirgilCertificateId):void {
        _wrap_VirgilCertificate_setId(cPtr, certificateId.cPtr);
    }

    public function publicKey():ByteArray {
        return _wrap_VirgilCertificate_publicKey(cPtr);
    }
}

public class VirgilTicket {
    public var cPtr:int;

    public static function create():VirgilTicket {
        var obj = new VirgilTicket();
        obj.cPtr = _wrap_new_VirgilTicket();
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilTicket(cPtr);
    }

    public function id():VirgilTicketId {
        var ticketId:VirgilTicketId = new VirgilTicketId();
        ticketId.cPtr = _wrap_VirgilTicket_id(cPtr);
        return ticketId;
    }

    public function setId(ticketId:VirgilTicketId):void {
        _wrap_VirgilTicket_setId(cPtr, ticketId.cPtr);
    }

    public function isUserIdTicket():Boolean {
        return _wrap_VirgilTicket_isUserIdTicket(cPtr);
    }

    public function asUserIdTicket():VirgilUserIdTicket {
        var userIdTicket:VirgilUserIdTicket = new VirgilUserIdTicket();
        userIdTicket.cPtr = _wrap_VirgilTicket_asUserIdTicket(cPtr);
        return userIdTicket;
    }

    public function isUserInfoTicket():Boolean {
        return _wrap_VirgilTicket_isUserInfoTicket(cPtr);
    }

    public function asUserInfoTicket():VirgilUserInfoTicket {
        var userInfoTicket:VirgilUserInfoTicket = new VirgilUserInfoTicket();
        userInfoTicket.cPtr = _wrap_VirgilTicket_asUserInfoTicket(cPtr);
        return userInfoTicket;
    }
}

public class VirgilUserIdType {
    public var cPtr:int;

    public static function email():VirgilUserIdType {
        var obj = new VirgilUserIdType();
        obj.cPtr = _wrap_VirgilUserIdType_email();
        return obj;
    }

    public static function phone():VirgilUserIdType {
        var obj = new VirgilUserIdType();
        obj.cPtr = _wrap_VirgilUserIdType_phone();
        return obj;
    }

    public static function fax():VirgilUserIdType {
        var obj = new VirgilUserIdType();
        obj.cPtr = _wrap_VirgilUserIdType_fax();
        return obj;
    }

    public static function domain():VirgilUserIdType {
        var obj = new VirgilUserIdType();
        obj.cPtr = _wrap_VirgilUserIdType_domain();
        return obj;
    }

    public static function macAddress():VirgilUserIdType {
        var obj = new VirgilUserIdType();
        obj.cPtr = _wrap_VirgilUserIdType_macAddress();
        return obj;
    }

    public static function application():VirgilUserIdType {
        var obj = new VirgilUserIdType();
        obj.cPtr = _wrap_VirgilUserIdType_application();
        return obj;
    }

    public function isEmail():Boolean {
        return _wrap_VirgilUserIdType_isEmail(cPtr);
    }

    public function isPhone():Boolean {
        return _wrap_VirgilUserIdType_isPhone(cPtr);
    }

    public function isFax():Boolean {
        return _wrap_VirgilUserIdType_isFax(cPtr);
    }

    public function isDomain():Boolean {
        return _wrap_VirgilUserIdType_isDomain(cPtr);
    }

    public function isMacAddress():Boolean {
        return _wrap_VirgilUserIdType_isMacAddress(cPtr);
    }

    public function isApplication():Boolean {
        return _wrap_VirgilUserIdType_isApplication(cPtr);
    }

    public function name():String {
        return _wrap_VirgilUserIdType_name(cPtr);
    }

    public function code():int {
        return _wrap_VirgilUserIdType_code(cPtr);
    }

    public function equals(other:VirgilUserIdType):Boolean {
        return _wrap_VirgilUserIdType_equals(cPtr, other.cPtr);
    }



}

public class VirgilUserIdTicket extends VirgilTicket {
    public static function create(userId:ByteArray, userIdType:VirgilUserIdType):VirgilUserIdTicket {
        var obj = new VirgilUserIdTicket();
        obj.cPtr = _wrap_new_VirgilUserIdTicket(userId, userIdType.cPtr);
        return obj;
    }

    override public function destroy():void {
        _wrap_delete_VirgilUserIdTicket(cPtr);
    }

    public function userId():ByteArray {
        return _wrap_VirgilUserIdTicket_userId(cPtr);
    }

    public function userIdType():VirgilUserIdType {
        var userIdType:VirgilUserIdType = new VirgilUserIdType();
        userIdType.cPtr = _wrap_VirgilUserIdTicket_userIdType(cPtr);
        return userIdType;
    }
}

public class VirgilUserInfoTicket extends VirgilTicket {
    public static function create(userFirstName:ByteArray, userLastName:ByteArray, userAge:uint)
            :VirgilUserInfoTicket {
        var obj = new VirgilUserInfoTicket();
        obj.cPtr = _wrap_new_VirgilUserInfoTicket(userFirstName, userLastName, userAge);
        return obj;
    }

    override public function destroy():void {
        _wrap_delete_VirgilUserInfoTicket(cPtr);
    }

    public function userFirstName():ByteArray {
        return _wrap_VirgilUserInfoTicket_userFirstName(cPtr);
    }

    public function userLastName():ByteArray {
        return _wrap_VirgilUserInfoTicket_userLastName(cPtr);
    }

    public function userAge():uint {
        return _wrap_VirgilUserInfoTicket_userAge(cPtr);
    }
}

public class VirgilSign {
    public var cPtr:int;

    public static function create(hashName:ByteArray, signedDigest:ByteArray,
            signerCertificateId:ByteArray):VirgilSign {
        var obj = new VirgilSign();
        obj.cPtr = _wrap_new_VirgilSign(hashName, signedDigest, signerCertificateId);
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilSign(cPtr);
    }

    public function id():VirgilSignId {
        var signId:VirgilSignId = new VirgilSignId();
        signId.cPtr = _wrap_VirgilSign_id(cPtr);
        return signId;
    }

    public function setId(signId:VirgilSignId):void {
        _wrap_VirgilSign_setId(cPtr, signId.cPtr);
    }

    public function hashName():ByteArray {
        return _wrap_VirgilSign_hashName(cPtr);
    }

    public function signedDigest():ByteArray {
        return _wrap_VirgilSign_signedDigest(cPtr);
    }

    public function signerCertificateId():ByteArray {
        return _wrap_VirgilSign_signerCertificateId(cPtr);
    }
}

public class VirgilKeyPair {
    public var cPtr:int;

    public static function create(publicKey:ByteArray, privateKey:ByteArray):VirgilKeyPair {
        var obj = new VirgilKeyPair();
        obj.cPtr = _wrap_new_VirgilKeyPair(publicKey, privateKey);
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilKeyPair(cPtr);
    }

    public function publicKey():ByteArray {
        return _wrap_VirgilKeyPair_publicKey(cPtr);
    }

    public function privateKey():ByteArray {
        return _wrap_VirgilKeyPair_privateKey(cPtr);
    }
}

public interface VirgilDataSink {
    function isGood():Boolean;
    function write(data:ByteArray):void;
}

public interface VirgilDataSource {
    function hasData():Boolean;
    function read():ByteArray;
}

public class VirgilDataSinkWrapper implements VirgilDataSink {
    private var dataOutput_:IDataOutput;

    function VirgilDataSinkWrapper(dataOutput:IDataOutput) {
        reset(dataOutput);
    }

    public function reset(dataOutput:IDataOutput):void {
        dataOutput_ = dataOutput;
    }

    public function isGood():Boolean {
        return true;
    }

    public function write(data:ByteArray):void {
        dataOutput_.writeBytes(data);
    }
}

public class VirgilDataSourceWrapper implements VirgilDataSource {
    private var dataInput_:IDataInput;

    function VirgilDataSourceWrapper(dataInput:IDataInput) {
        reset(dataInput);
    }

    public function reset(dataInput:IDataInput):void {
        dataInput_ = dataInput;
    }

    public function hasData():Boolean {
        return dataInput_.bytesAvailable > 0;
    }

    public function read():ByteArray {
        var data:ByteArray = new ByteArray();
        dataInput_.readBytes(data);
        return data;
    }
}

public class VirgilDataMarshaller {
    public var cPtr:int;

    public function destroy():void {
        throw new Error("This method MUST be implemented in the derived class.");
    }

    public function marshalAccount(account:VirgilAccount):ByteArray {
        return _wrap_VirgilDataMarshaller_marshalVirgilAccount(cPtr, account.cPtr);
    }

    public function marshalCertificate(certificate:VirgilCertificate):ByteArray {
        return _wrap_VirgilDataMarshaller_marshalVirgilCertificate(cPtr, certificate.cPtr);
    }

    public function marshalTicket(ticket:VirgilTicket):ByteArray {
        return _wrap_VirgilDataMarshaller_marshalVirgilTicket(cPtr, ticket.cPtr);
    }

    public function marshalSign(sign:VirgilSign):ByteArray {
        return _wrap_VirgilDataMarshaller_marshalVirgilSign(cPtr, sign.cPtr);
    }

    public function demarshalAccount(data:ByteArray):VirgilAccount {
        var account:VirgilAccount = new VirgilAccount();
        account.cPtr = _wrap_VirgilDataMarshaller_demarshalVirgilAccount(cPtr, data);
        return account;
    }

    public function demarshalCertificate(data:ByteArray):VirgilCertificate {
        var certificate:VirgilCertificate = new VirgilCertificate();
        certificate.cPtr = _wrap_VirgilDataMarshaller_demarshalVirgilCertificate(cPtr, data);
        return certificate;s
    }

    public function demarshalTicket(data:ByteArray):VirgilTicket {
        var ticket:VirgilTicket = new VirgilTicket();
        ticket.cPtr = _wrap_VirgilDataMarshaller_demarshalVirgilTicket(cPtr, data);
        return ticket;
    }

    public function demarshalSign(data:ByteArray):VirgilSign {
        var sign:VirgilSign = new VirgilSign();
        sign.cPtr = _wrap_VirgilDataMarshaller_demarshalVirgilSign(cPtr, data);
        return sign;
    }

}

public class VirgilJsonDataMarshaller extends VirgilDataMarshaller {

    public static function create():VirgilJsonDataMarshaller {
        var obj = new VirgilJsonDataMarshaller();
        obj.cPtr = _wrap_new_VirgilJsonDataMarshaller();
        return obj;
    }

    public override function destroy():void {
        _wrap_delete_VirgilJsonDataMarshaller(cPtr);
    }
}

public class VirgilAsn1DataMarshaller extends VirgilDataMarshaller {

    public static function create():VirgilAsn1DataMarshaller {
        var obj = new VirgilAsn1DataMarshaller();
        obj.cPtr = _wrap_new_VirgilAsn1DataMarshaller();
        return obj;
    }

    public override function destroy():void {
        _wrap_delete_VirgilAsn1DataMarshaller(cPtr);
    }
}

public class VirgilCipher {
    public var cPtr:int;

    public static function create():VirgilCipher {
        var obj = new VirgilCipher();
        obj.cPtr = _wrap_new_VirgilCipher();
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilCipher(cPtr);
    }

    public static function generateKeyPair():VirgilKeyPair {
        var keyPair:VirgilKeyPair = new VirgilKeyPair();
        keyPair.cPtr = _wrap_VirgilCipher_generateKeyPair();
        return keyPair;
    }

    public static function reencryptKey(encryptionKey:ByteArray, publicKey:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):ByteArray {
        return _wrap_VirgilCipher_reencryptKey(encryptionKey, publicKey, privateKey, privateKeyPassword);
    }

    public function encrypt(dataSource:VirgilDataSource, dataSink:VirgilDataSink, asPublicKey:ByteArray):ByteArray {
        return _wrap_VirgilCipher_encrypt(cPtr, dataSource, dataSink, asPublicKey);
    }

    public function decrypt(dataSource:VirgilDataSource, dataSink:VirgilDataSink, encryptionKey:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):void {
        if (privateKeyPassword == null) {
            privateKeyPassword = new ByteArray();
        }
        return _wrap_VirgilCipher_decrypt(cPtr, dataSource, dataSink, encryptionKey, privateKey, privateKeyPassword);
    }

    public function encryptWithPassword(data:ByteArray, password:ByteArray):ByteArray {
        return _wrap_VirgilCipher_encryptWithPassword(cPtr, data, password);
    }

    public function decryptWithPassword(data:ByteArray, password:ByteArray):ByteArray {
        return _wrap_VirgilCipher_decryptWithPassword(cPtr, data, password);
    }
}

public class VirgilChunkCipher {
    public var cPtr:int;

    public static function create():VirgilChunkCipher {
        var obj = new VirgilChunkCipher();
        obj.cPtr = _wrap_new_VirgilChunkCipher();
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilChunkCipher(cPtr);
    }

    public function adjustEncryptionChunkSize(preferredChunkSize:uint):uint {
        return _wrap_VirgilChunkCipher_adjustEncryptionChunkSize(cPtr, preferredChunkSize);
    }

    public function adjustDecryptionChunkSize(encryptionChunkSize:uint):uint {
        return _wrap_VirgilChunkCipher_adjustDecryptionChunkSize(cPtr, encryptionChunkSize);
    }

    public function startEncryption(publicKey:ByteArray):ByteArray {
        return _wrap_VirgilChunkCipher_startEncryption(cPtr, publicKey);
    }

    public function startDecryption(encryptionKey:ByteArray, privateKey:ByteArray,
                privateKeyPassword:ByteArray = null):void {
        return _wrap_VirgilChunkCipher_startDecryption(cPtr, encryptionKey, privateKey, privateKeyPassword);
    }

    public function process(data:ByteArray):ByteArray {
        return _wrap_VirgilChunkCipher_process(cPtr, data);
    }

    public function finalize():void {
        return _wrap_VirgilChunkCipher_finalize(cPtr);
    }
}

public class VirgilSigner {
    public var cPtr:int;

    public static function create():VirgilSigner {
        var obj = new VirgilSigner();
        obj.cPtr = _wrap_new_VirgilSigner();
        return obj;
    }

    public function destroy():void {
        _wrap_delete_VirgilSigner(cPtr);
    }

    public function sign(dataSource:VirgilDataSource, signerCertificateId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):VirgilSign {
        if (privateKeyPassword == null) {
            privateKeyPassword = new ByteArray();
        }
        var sign:VirgilSign = new VirgilSign();
        sign.cPtr = _wrap_VirgilSigner_sign(cPtr, dataSource, signerCertificateId, privateKey, privateKeyPassword);
        return sign;
    }

    public function verify(dataSource:VirgilDataSource, sign:VirgilSign, publicKey:ByteArray):Boolean {
        return _wrap_VirgilSigner_verify(cPtr, dataSource, sign.cPtr, publicKey);
    }

    public function signTicket(ticket:VirgilTicket, signerCertificateId:ByteArray,
            privateKey:ByteArray, privateKeyPassword:ByteArray = null):VirgilSign {
        if (privateKeyPassword == null) {
            privateKeyPassword = new ByteArray();
        }
        var sign:VirgilSign = new VirgilSign();
        sign.cPtr = _wrap_VirgilSigner_signTicket(cPtr, ticket.cPtr, signerCertificateId, privateKey, privateKeyPassword);
        return sign;
    }

    public function verifyTicket(ticket:VirgilTicket, sign:VirgilSign, publicKey:ByteArray):Boolean {
        return _wrap_VirgilSigner_verifyTicket(cPtr, ticket.cPtr, sign.cPtr, publicKey);
    }
}

}
