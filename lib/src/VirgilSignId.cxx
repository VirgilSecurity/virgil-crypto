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

#include "virgil/service/data/VirgilSignId.h"
using virgil::service::data::VirgilSignId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <json/json.h>

/**
 * @name JSON Keys
 */
///@{
static const char *kJsonKey_SignId = "sign_id";
///@}

VirgilByteArray VirgilSignId::signId() const {
    return signId_;
}

void VirgilSignId::setSignId(const VirgilByteArray& signId) {
    signId_ = signId;
}

bool VirgilSignId::isEmpty() const {
    return signId_.empty() || VirgilTicketId::isEmpty();
}

void VirgilSignId::clear() {
    signId_.clear();
    VirgilTicketId::clear();
}

size_t VirgilSignId::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t writtenBytes = asn1Writer.writeUTF8String(signId_);
    return VirgilTicketId::asn1Write(asn1Writer, writtenBytes + childWrittenBytes);
}

void VirgilSignId::asn1Read(VirgilAsn1Reader& asn1Reader) {
    VirgilTicketId::asn1Read(asn1Reader);
    signId_ = asn1Reader.readUTF8String();
}

Json::Value VirgilSignId::jsonWrite(Json::Value& childValue) const {
    childValue[kJsonKey_SignId] = virgil::bytes2str(signId_);
    return VirgilTicketId::jsonWrite(childValue);
}

Json::Value VirgilSignId::jsonRead(const Json::Value& parentValue) {
    Json::Value childValue = VirgilTicketId::jsonRead(parentValue);
    signId_ = jsonGetStringAsByteArray(childValue, kJsonKey_SignId);
    return childValue;
}
