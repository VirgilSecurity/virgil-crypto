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

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

/**
 * @name ASN.1 tags
 */
///@{
static const unsigned char kASN1_IdTag = 0;
///@}

/**
 * @name JSON Keys
 */
///@{
static const char *kJsonKey_HashName = "hash_name";
static const char *kJsonKey_SignedDigest = "signed_digest";
static const char *kJsonKey_SignerCertificateId = "signer_certificate_id";
///@}

VirgilSign::VirgilSign() {
}

VirgilSign::VirgilSign(const VirgilByteArray& hashName, const VirgilByteArray& signedDigest,
                const VirgilByteArray& signerCertificateId)
        : hashName_(hashName), signedDigest_(signedDigest), signerCertificateId_(signerCertificateId) {
}

VirgilSign::~VirgilSign() throw() {
}

VirgilByteArray VirgilSign::hashName() const {
    return hashName_;
}

VirgilByteArray VirgilSign::signedDigest() const {
    return signedDigest_;
}

VirgilByteArray VirgilSign::signerCertificateId() const {
    return signerCertificateId_;
}

size_t VirgilSign::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t writtenBytes = 0;
    writtenBytes += asn1Writer.writeOctetString(signedDigest_);
    writtenBytes += asn1Writer.writeUTF8String(signerCertificateId_);
    writtenBytes += asn1Writer.writeUTF8String(hashName_);
    if (!id().isEmpty()) {
        size_t idLen = id().asn1Write(asn1Writer);
        writtenBytes += idLen;
        writtenBytes += asn1Writer.writeContextTag(kASN1_IdTag, idLen);
    }
    writtenBytes += asn1Writer.writeSequence(writtenBytes + childWrittenBytes);
    return writtenBytes + childWrittenBytes;
}

void VirgilSign::asn1Read(VirgilAsn1Reader& asn1Reader) {
    asn1Reader.readSequence();
    if (asn1Reader.readContextTag(kASN1_IdTag) > 0) {
        id().asn1Read(asn1Reader);
    }
    hashName_ = asn1Reader.readUTF8String();
    signerCertificateId_ = asn1Reader.readUTF8String();
    signedDigest_ = asn1Reader.readOctetString();
}

Json::Value VirgilSign::jsonWrite(Json::Value& childValue) const {
    childValue[kJsonKey_HashName] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(hashName_);
    childValue[kJsonKey_SignedDigest] = jsonRawDataToValue(signedDigest_);
    childValue[kJsonKey_SignerCertificateId] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(signerCertificateId_);
    if (!id().isEmpty()) {
        Json::Value idChildrenValue(Json::objectValue);
        Json::Value idValue = id().jsonWrite(idChildrenValue);
        return jsonMergeObjects(childValue, idValue);
    }
    return childValue;
}

Json::Value VirgilSign::jsonRead(const Json::Value& parentValue) {
    if (parentValue["id"].isObject()) {
        (void)id().jsonRead(parentValue);
    }
    hashName_ = jsonGetStringAsByteArray(parentValue, kJsonKey_HashName);
    signedDigest_ = jsonRawDataFromValue(parentValue[kJsonKey_SignedDigest]);
    signerCertificateId_ = jsonGetStringAsByteArray(parentValue, kJsonKey_SignerCertificateId);
    return parentValue;
}
