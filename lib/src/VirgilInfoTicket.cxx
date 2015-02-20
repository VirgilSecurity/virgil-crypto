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
 *     (1) Redistributions of source type must retain the above copyright
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

#include <virgil/service/data/VirgilInfoTicket.h>
using virgil::service::data::VirgilInfoTicket;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <map>
#include <string>
#include <sstream>

/**
 * @name JSON Keys
 */
///@{
static const char *kJsonKey_ClassName = "class_name";
static const char *kJsonKey_Type = "type";
static const char *kJsonKey_Value = "value";
///@}
/**
 * @name Marshalling class-specific values
 */
///@{
static const char *kInfoTicket_ClassName = "info_ticket";
///@}

class InfoTicketTypeConverter {
private:
public:
    InfoTicketTypeConverter() {
        toString_[VirgilInfoTicketType_FirstName] = "first_name";
        toString_[VirgilInfoTicketType_LastName] = "last_name";
        toString_[VirgilInfoTicketType_MiddleName] = "middle_name";
        toString_[VirgilInfoTicketType_Nickname] = "nickname";
        toString_[VirgilInfoTicketType_BirthDate] = "birth_date";

        std::map<VirgilInfoTicketType, std::string>::const_iterator toStringIt = toString_.begin();
        for (; toStringIt != toString_.end(); ++toStringIt) {
            toType_[toStringIt->second] = toStringIt->first;
        }
    }

    VirgilInfoTicketType operator()(const std::string& name) const {
        std::map<std::string, VirgilInfoTicketType>::const_iterator it = toType_.find(name);
        if (it == toType_.end()) {
            std::ostringstream message;
            message << "VirgilInfoTicketType: cannot find type for given name: " << name << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }

    std::string operator()(VirgilInfoTicketType type) const {
        std::map<VirgilInfoTicketType, std::string>::const_iterator it = toString_.find(type);
        if (it == toString_.end()) {
            std::ostringstream message;
            message << "VirgilInfoTicketType: cannot find name for given type: " << type << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }
private:
    std::map<VirgilInfoTicketType, std::string> toString_;
    std::map<std::string, VirgilInfoTicketType> toType_;
};

static const InfoTicketTypeConverter gInfoTicketTypeConverter;


VirgilInfoTicket::VirgilInfoTicket()
        : type_(VirgilInfoTicketType_None), value_() {
}

VirgilInfoTicket::VirgilInfoTicket(VirgilInfoTicketType type, const VirgilByteArray& value)
        : type_(type), value_(value) {
}

VirgilInfoTicket::~VirgilInfoTicket() throw() {
}

VirgilByteArray VirgilInfoTicket::value() const {
    return value_;
}

VirgilInfoTicketType VirgilInfoTicket::type() const {
    return type_;
}

bool VirgilInfoTicket::isInfoTicket() const {
    return true;
}

size_t VirgilInfoTicket::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t writtenBytes = 0;
    writtenBytes += asn1Writer.writeUTF8String(value_);
    writtenBytes += asn1Writer.writeUTF8String(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(gInfoTicketTypeConverter(type_)));
    writtenBytes += asn1Writer.writeUTF8String(VIRGIL_BYTE_ARRAY_FROM_C_STRING(kInfoTicket_ClassName));

    return VirgilTicket::asn1Write(asn1Writer, writtenBytes + childWrittenBytes);
}

void VirgilInfoTicket::asn1Read(VirgilAsn1Reader& asn1Reader) {
    VirgilTicket::asn1Read(asn1Reader);
    if (VIRGIL_BYTE_ARRAY_TO_STD_STRING(asn1Reader.readUTF8String()) != std::string(kInfoTicket_ClassName)) {
        throw VirgilException(std::string("VirgilInfoTicket: ") +
                "Wrong class name for this class.");
    }
    type_ = gInfoTicketTypeConverter(VIRGIL_BYTE_ARRAY_TO_STD_STRING(asn1Reader.readUTF8String()));
    value_ = asn1Reader.readUTF8String();
}

Json::Value VirgilInfoTicket::jsonWrite(Json::Value& childValue) const {
    childValue[kJsonKey_ClassName] = kInfoTicket_ClassName;
    childValue[kJsonKey_Type] = gInfoTicketTypeConverter(type_);
    childValue[kJsonKey_Value] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(value_);
    return VirgilTicket::jsonWrite(childValue);
}

Json::Value VirgilInfoTicket::jsonRead(const Json::Value& parentValue) {
    Json::Value childValue = VirgilTicket::jsonRead(parentValue);
    if (jsonGetString(childValue, kJsonKey_ClassName) != std::string(kInfoTicket_ClassName)) {
        throw VirgilException(std::string("VirgilInfoTicket: ") +
                "Wrong class name for this class.");
    }
    type_ = gInfoTicketTypeConverter(jsonGetString(childValue, kJsonKey_Type));
    value_ = jsonGetStringAsByteArray(childValue, kJsonKey_Value);
    return childValue;
}
