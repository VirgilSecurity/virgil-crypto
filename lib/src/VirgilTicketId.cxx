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

#include "virgil/service/data/VirgilTicketId.h"
using virgil::service::data::VirgilTicketId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/asn1/VirgilAsn1Reader.h>
using virgil::crypto::asn1::VirgilAsn1Reader;

#include <virgil/crypto/asn1/VirgilAsn1Writer.h>
using virgil::crypto::asn1::VirgilAsn1Writer;

#include <json/json.h>

/**
 * @name JSON Keys
 */
///@{
static const char *kJsonKey_TicketId = "ticket_id";
///@}

VirgilByteArray VirgilTicketId::ticketId() const {
    return ticketId_;
}

void VirgilTicketId::setTicketId(const VirgilByteArray& ticketId) {
    ticketId_ = ticketId;
}

bool VirgilTicketId::isEmpty() const {
    return ticketId_.empty() || VirgilCertificateId::isEmpty();
}

void VirgilTicketId::clear() {
    ticketId_.clear();
    VirgilCertificateId::clear();
}

size_t VirgilTicketId::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t writtenBytes = asn1Writer.writeUTF8String(ticketId_);
    return VirgilCertificateId::asn1Write(asn1Writer, writtenBytes + childWrittenBytes);
}

void VirgilTicketId::asn1Read(VirgilAsn1Reader& asn1Reader) {
    VirgilCertificateId::asn1Read(asn1Reader);
    ticketId_ = asn1Reader.readUTF8String();
}

Json::Value VirgilTicketId::jsonWrite(Json::Value& childValue) const {
    childValue[kJsonKey_TicketId] = virgil::bytes2str(ticketId_);
    return VirgilCertificateId::jsonWrite(childValue);
}

Json::Value VirgilTicketId::jsonRead(const Json::Value& parentValue) {
    Json::Value childValue = VirgilCertificateId::jsonRead(parentValue);
    ticketId_ = jsonGetStringAsByteArray(childValue, kJsonKey_TicketId);
    return childValue;
}
