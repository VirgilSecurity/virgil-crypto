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

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilUniqueTicket.h>
using virgil::service::data::VirgilUniqueTicket;

#include <virgil/service/data/VirgilInfoTicket.h>
using virgil::service::data::VirgilInfoTicket;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <string>

/**
 * @name JSON Keys
 */
///@{
static const char *kJsonKey_ClassName = "class_name";
///@}

static VirgilTicket * ticketFromClassName(const std::string& className) {
    if (className == VirgilUniqueTicket::ClassName()) {
        return new VirgilUniqueTicket();
    }
    if (className == VirgilInfoTicket::ClassName()) {
        return new VirgilInfoTicket();
    }
    throw VirgilException(std::string("VirgilTicket:") +
            "Can not find implementation for ticket with class name: " + className + ".");
}

VirgilTicket * VirgilTicket::createFromAsn1(const VirgilByteArray& asn1) {
    VirgilAsn1Reader asn1Reader(asn1);
    asn1Reader.readSequence();
    VirgilByteArray className = asn1Reader.readUTF8String();
    VirgilTicket *ticket = ticketFromClassName(VIRGIL_BYTE_ARRAY_TO_STD_STRING(className));
    ticket->fromAsn1(asn1);
    return ticket;
}

VirgilTicket * VirgilTicket::createFromJson(const VirgilByteArray& json) {
    Json::Reader reader(Json::Features::strictMode());
    Json::Value rootObject;
    if (!reader.parse(VIRGIL_BYTE_ARRAY_TO_STD_STRING(json), rootObject)) {
        throw VirgilException(reader.getFormattedErrorMessages());
    }
    std::string className = jsonGetString(rootObject, kJsonKey_ClassName);
    VirgilTicket *ticket = ticketFromClassName(className);
    ticket->fromJson(json);
    return ticket;
}

VirgilTicket::~VirgilTicket() throw() {}

bool VirgilTicket::isUniqueTicket() const { return false; }

VirgilUniqueTicket& VirgilTicket::asUniqueTicket() {
    if (!isUniqueTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUniqueTicket.");
    }
    return dynamic_cast<VirgilUniqueTicket&>(*this);
}

const VirgilUniqueTicket& VirgilTicket::asUniqueTicket() const {
    if (!isUniqueTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUniqueTicket.");
    }
    return dynamic_cast<const VirgilUniqueTicket&>(*this);
}

bool VirgilTicket::isInfoTicket() const { return false; }

VirgilInfoTicket& VirgilTicket::asInfoTicket() {
    if (!isInfoTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilInfoTicket.");
    }
    return dynamic_cast<VirgilInfoTicket&>(*this);
}

const VirgilInfoTicket& VirgilTicket::asInfoTicket() const {
    if (!isInfoTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilInfoTicket.");
    }
    return dynamic_cast<const VirgilInfoTicket&>(*this);
}

size_t VirgilTicket::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t writtenBytes = 0;
    writtenBytes += id().asn1Write(asn1Writer);
    writtenBytes += asn1Writer.writeUTF8String(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(className()));
    writtenBytes += asn1Writer.writeSequence(writtenBytes + childWrittenBytes);
    return writtenBytes + childWrittenBytes;
}

void VirgilTicket::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();
    VirgilByteArray name = asn1Reader.readUTF8String();
    if (VIRGIL_BYTE_ARRAY_TO_STD_STRING(name) != className()) {
        throw VirgilException(std::string("VirgilTicket: ") +
                "Wrong class name for this class. " +
                "Found: " + VIRGIL_BYTE_ARRAY_TO_STD_STRING(name) +
                ", but expected: " + className() + ".");
    }
    id().asn1Read(asn1Reader);
}

Json::Value VirgilTicket::jsonWrite(Json::Value& childValue) const {
    Json::Value idChildrenValue(Json::objectValue);
    Json::Value idValue = id().jsonWrite(idChildrenValue);
    childValue[kJsonKey_ClassName] = className();
    return jsonMergeObjects(childValue, idValue);
}

Json::Value VirgilTicket::jsonRead(const Json::Value& parentValue) {
    id().jsonRead(parentValue);
    std::string name = jsonGetString(parentValue, kJsonKey_ClassName);
    if (name != className()) {
        throw VirgilException(std::string("VirgilTicket: ") +
                "Wrong class name for this class. " +
                "Found: " + name + ", but expected: " + className() + ".");
    }
    return parentValue;
}
