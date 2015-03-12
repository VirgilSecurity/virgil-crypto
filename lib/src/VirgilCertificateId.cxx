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

#include "virgil/service/data/VirgilCertificateId.h"
using virgil::service::data::VirgilCertificateId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

/**
 * @name JSON Keys
 */
///@{
static const char *kJsonKey_CertificateId = "certificate_id";
///@}

VirgilByteArray VirgilCertificateId::certificateId() const {
    return certificateId_;
}

void VirgilCertificateId::setCertificateId(const VirgilByteArray& certificateId) {
    certificateId_ = certificateId;
}

bool VirgilCertificateId::isEmpty() const {
    return certificateId_.empty() || VirgilAccountId::isEmpty();
}

void VirgilCertificateId::clear() {
    certificateId_.clear();
    VirgilAccountId::clear();
}

size_t VirgilCertificateId::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t writtenBytes = asn1Writer.writeUTF8String(certificateId_);
    return VirgilAccountId::asn1Write(asn1Writer, writtenBytes + childWrittenBytes);
}

void VirgilCertificateId::asn1Read(VirgilAsn1Reader& asn1Reader) {
    VirgilAccountId::asn1Read(asn1Reader);
    certificateId_ = asn1Reader.readUTF8String();
}

Json::Value VirgilCertificateId::jsonWrite(Json::Value& childValue) const {
    childValue[kJsonKey_CertificateId] = virgil_byte_array_to_std_string(certificateId_);
    return VirgilAccountId::jsonWrite(childValue);
}

Json::Value VirgilCertificateId::jsonRead(const Json::Value& parentValue) {
    Json::Value childValue = VirgilAccountId::jsonRead(parentValue);
    certificateId_ = jsonGetStringAsByteArray(childValue, kJsonKey_CertificateId);
    return childValue;
}


