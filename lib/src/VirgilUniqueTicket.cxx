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

#include <virgil/service/data/VirgilUniqueTicket.h>
using virgil::service::data::VirgilUniqueTicket;

#include <virgil/service/data/VirgilUniqueTicketType.h>

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <string>

/**
 * @name JSON Keys
 */
///@{
static const char *kJsonKey_Type = "type";
static const char *kJsonKey_Value = "value";
///@}
/**
 * @name Marshalling class-specific values
 */
///@{
static const char *kUniqueTicket_ClassName = "unique_ticket";
///@}

VirgilUniqueTicket::VirgilUniqueTicket()
        : type_(VirgilUniqueTicketType_None), value_() {
}

VirgilUniqueTicket::VirgilUniqueTicket(VirgilUniqueTicketType type, const VirgilByteArray& value)
        : type_(type), value_(value) {
}

VirgilUniqueTicket::~VirgilUniqueTicket() throw() {
}

VirgilByteArray VirgilUniqueTicket::value() const {
    return value_;
}

VirgilUniqueTicketType VirgilUniqueTicket::type() const {
    return type_;
}

bool VirgilUniqueTicket::isUniqueTicket() const {
    return true;
}

size_t VirgilUniqueTicket::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t writtenBytes = 0;
    writtenBytes += asn1Writer.writeUTF8String(value_);
    writtenBytes += asn1Writer.writeUTF8String(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(
            virgil_unique_ticket_type_to_string(type_)));
    return VirgilTicket::asn1Write(asn1Writer, writtenBytes + childWrittenBytes);
}

void VirgilUniqueTicket::asn1Read(VirgilAsn1Reader& asn1Reader) {
    VirgilTicket::asn1Read(asn1Reader);
    type_ = virgil_unique_ticket_type_from_string(VIRGIL_BYTE_ARRAY_TO_STD_STRING(asn1Reader.readUTF8String()));
    value_ = asn1Reader.readUTF8String();
}

Json::Value VirgilUniqueTicket::jsonWrite(Json::Value& childValue) const {
    childValue[kJsonKey_Type] = virgil_unique_ticket_type_to_string(type_);
    childValue[kJsonKey_Value] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(value_);
    return VirgilTicket::jsonWrite(childValue);
}

Json::Value VirgilUniqueTicket::jsonRead(const Json::Value& parentValue) {
    Json::Value childValue = VirgilTicket::jsonRead(parentValue);
    type_ = virgil_unique_ticket_type_from_string(jsonGetString(childValue, kJsonKey_Type));
    value_ = jsonGetStringAsByteArray(childValue, kJsonKey_Value);
    return childValue;
}

std::string VirgilUniqueTicket::ClassName() {
    return kUniqueTicket_ClassName;
}

std::string VirgilUniqueTicket::className() const {
    return VirgilUniqueTicket::ClassName();
}
