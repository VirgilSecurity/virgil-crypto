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

package com.virgilsecurity.extension {

import C_Run.*;
import com.adobe.flascc.swig.*;
import flash.utils.ByteArray;
import flash.utils.IDataInput;
import flash.utils.IDataOutput;

public interface ICObject {
    function get cPtr():int;
    function set cPtr(value:int):void;
}

public class CObject {
    private var cPtr_:int;
    public function get cPtr():int {
        return cPtr_;
    }
    public function set cPtr(value:int):void {
        cPtr_ = value;
    }
}

public interface IVirgilAsn1Compatible extends ICObject {
    function toAsn1():ByteArray;
    function fromAsn1(asn1:ByteArray):void;
}

public interface IVirgilJsonCompatible extends ICObject {
    function toJson():ByteArray;
    function fromJson(asn1:ByteArray):void;
}


public class VirgilUniqueTicketType {
    public static const None : VirgilUniqueTicketType = new VirgilUniqueTicketType(0);
    public static const Email : VirgilUniqueTicketType = new VirgilUniqueTicketType(1);
    public static const Phone : VirgilUniqueTicketType = new VirgilUniqueTicketType(2);
    public static const Fax : VirgilUniqueTicketType = new VirgilUniqueTicketType(3);
    public static const Domain : VirgilUniqueTicketType = new VirgilUniqueTicketType(4);
    public static const MacAddress : VirgilUniqueTicketType = new VirgilUniqueTicketType(5);
    public static const Application : VirgilUniqueTicketType = new VirgilUniqueTicketType(6);

    private static var enumCreated_:Boolean = false;
    { enumCreated_ = true; }

    private var code_ : String;
    public function VirgilUniqueTicketType(code:uint) {
        if (enumCreated_) {
            throw new Error("VirgilUniqueTicketType: The enum is already created.");
        }
        code_ = code;
    }
    public function get code():uint {
        return code_;
    }
    public static function fromCode(code:uint):VirgilUniqueTicketType {
        switch (code) {
            case 0:
                return VirgilUniqueTicketType.None;
            case 1:
                return VirgilUniqueTicketType.Email;
            case 2:
                return VirgilUniqueTicketType.Phone;
            case 3:
                return VirgilUniqueTicketType.Fax;
            case 4:
                return VirgilUniqueTicketType.Domain;
            case 5:
                return VirgilUniqueTicketType.MacAddress;
            case 6:
                return VirgilUniqueTicketType.Application;
            default :
                throw new Error("VirgilUniqueTicketType: Unsupported enum code was given: " + code + ".");
        }
    }
}

public class VirgilInfoTicketType {
    public static const None : VirgilInfoTicketType = new VirgilInfoTicketType(0);
    public static const FirstName : VirgilInfoTicketType = new VirgilInfoTicketType(1);
    public static const LastName : VirgilInfoTicketType = new VirgilInfoTicketType(2);
    public static const MiddleName : VirgilInfoTicketType = new VirgilInfoTicketType(3);
    public static const Nickname : VirgilInfoTicketType = new VirgilInfoTicketType(4);
    public static const BirthDate : VirgilInfoTicketType = new VirgilInfoTicketType(5);

    private static var enumCreated_:Boolean = false;
    { enumCreated_ = true; }

    private var code_ : String;
    public function VirgilInfoTicketType(code:uint) {
        if (enumCreated_) {
            throw new Error("VirgilInfoTicketType: The enum is already created.");
        }
        code_ = code;
    }
    public function get code():uint {
        return code_;
    }
    public static function fromCode(code:uint):VirgilInfoTicketType {
        switch (code) {
            case 0:
                return VirgilInfoTicketType.None;
            case 1:
                return VirgilInfoTicketType.FirstName;
            case 2:
                return VirgilInfoTicketType.LastName;
            case 3:
                return VirgilInfoTicketType.MiddleName;
            case 4:
                return VirgilInfoTicketType.Nickname;
            case 5:
                return VirgilInfoTicketType.BirthDate;
            default :
                throw new Error("VirgilInfoTicketType: Unsupported enum code was given: " + code + ".");
        }
    }
}

public interface IVirgilDataSink {
    function isGood():Boolean;
    function write(data:ByteArray):void;
}

public interface IVirgilDataSource {
    function hasData():Boolean;
    function read():ByteArray;
}

public class VirgilDataSink implements IVirgilDataSink {
    private var dataOutput_:IDataOutput;
    function VirgilDataSink(dataOutput:IDataOutput) {
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

public class VirgilDataSource implements IVirgilDataSource {
    private var dataInput_:IDataInput;
    private var chunkSize_:uint;
    function VirgilDataSource(dataInput:IDataInput, chunkSize:uint = 1024 * 1024) {
        chunkSize_ = chunkSize;
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
        dataInput_.readBytes(data, 0, Math.min(chunkSize_, dataInput_.bytesAvailable));
        return data;
    }
}

}
