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

#include <virgil/crypto/VirgilCustomParams.h>
using virgil::crypto::VirgilCustomParams;

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <virgil/crypto/asn1/VirgilAsn1Reader.h>
using virgil::crypto::asn1::VirgilAsn1Reader;

#include <virgil/crypto/asn1/VirgilAsn1Writer.h>
using virgil::crypto::asn1::VirgilAsn1Writer;

#include <cstddef>
#include <vector>

/**
 * @name ASN.1 Constants
 */
///@{
static const unsigned char kCMS_IntegerValueTag = 0;
static const unsigned char kCMS_StringValueTag = 1;
static const unsigned char kCMS_DataValueTag = 2;
///@}

VirgilCustomParams::~VirgilCustomParams() throw() {
}

bool VirgilCustomParams::isEmpty() const {
    return intValues_.empty() && stringValues_.empty() && dataValues_.empty();
}

void VirgilCustomParams::setInteger(const VirgilByteArray& key, int value) {
    intValues_[key] = value;
}

int VirgilCustomParams::getInteger(const VirgilByteArray& key) const {
    std::map<VirgilByteArray, int>::const_iterator keyValue = intValues_.find(key);
    if (keyValue != intValues_.end()) {
        return keyValue->second;
    } else {
        throw VirgilCryptoException(std::string("VirgilCustomParams") +
                "Key '" + virgil_byte_array_to_std_string(key) + "' is not found.");
    }
}

void VirgilCustomParams::removeInteger(const VirgilByteArray& key) {
    intValues_.erase(key);
}

void VirgilCustomParams::setString(const VirgilByteArray& key, const VirgilByteArray& value) {
    stringValues_[key] = value;
}

VirgilByteArray VirgilCustomParams::getString(const VirgilByteArray& key) const {
    std::map<VirgilByteArray, VirgilByteArray>::const_iterator keyValue = stringValues_.find(key);
    if (keyValue != stringValues_.end()) {
        return keyValue->second;
    } else {
        throw VirgilCryptoException(std::string("VirgilCustomParams") +
                "Key '" + virgil_byte_array_to_std_string(key) + "' is not found.");
    }
}

void VirgilCustomParams::removeString(const VirgilByteArray& key) {
    stringValues_.erase(key);
}

void VirgilCustomParams::setData(const VirgilByteArray& key, const VirgilByteArray& value) {
    dataValues_[key] = value;
}

VirgilByteArray VirgilCustomParams::getData(const VirgilByteArray& key) const {
    std::map<VirgilByteArray, VirgilByteArray>::const_iterator keyValue = dataValues_.find(key);
    if (keyValue != dataValues_.end()) {
        return keyValue->second;
    } else {
        throw VirgilCryptoException(std::string("VirgilCustomParams") +
                "Key '" + virgil_byte_array_to_std_string(key) + "' is not found.");
    }
}

void VirgilCustomParams::removeData(const VirgilByteArray& key) {
    dataValues_.erase(key);
}

void VirgilCustomParams::clear() {
    intValues_.clear();
    stringValues_.clear();
    dataValues_.clear();
}

size_t VirgilCustomParams::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    std::vector<VirgilByteArray> keyValues;

    for (std::map<VirgilByteArray, int>::const_iterator it = intValues_.begin();
            it != intValues_.end(); ++it) {

        VirgilAsn1Writer keyValueAsn1Writer;
        size_t len = 0;
        len += keyValueAsn1Writer.writeInteger(it->second);
        len += keyValueAsn1Writer.writeContextTag(kCMS_IntegerValueTag, len);
        len += keyValueAsn1Writer.writeUTF8String(it->first);
        len += keyValueAsn1Writer.writeSequence(len);

        keyValues.push_back(keyValueAsn1Writer.finish());
    }

    for (std::map<VirgilByteArray, VirgilByteArray>::const_iterator it = stringValues_.begin();
            it != stringValues_.end(); ++it) {

        VirgilAsn1Writer keyValueAsn1Writer;
        size_t len = 0;
        len += keyValueAsn1Writer.writeUTF8String(it->second);
        len += keyValueAsn1Writer.writeContextTag(kCMS_StringValueTag, len);
        len += keyValueAsn1Writer.writeUTF8String(it->first);
        len += keyValueAsn1Writer.writeSequence(len);

        keyValues.push_back(keyValueAsn1Writer.finish());
    }

    for (std::map<VirgilByteArray, VirgilByteArray>::const_iterator it = dataValues_.begin();
            it != dataValues_.end(); ++it) {

        VirgilAsn1Writer keyValueAsn1Writer;
        size_t len = 0;
        len += keyValueAsn1Writer.writeOctetString(it->second);
        len += keyValueAsn1Writer.writeContextTag(kCMS_DataValueTag, len);
        len += keyValueAsn1Writer.writeUTF8String(it->first);
        len += keyValueAsn1Writer.writeSequence(len);

        keyValues.push_back(keyValueAsn1Writer.finish());
    }

    size_t len = asn1Writer.writeSet(keyValues);
    return len + childWrittenBytes;
}

void VirgilCustomParams::asn1Read(VirgilAsn1Reader& asn1Reader) {
    intValues_.clear();
    stringValues_.clear();
    dataValues_.clear();

    size_t setLen = asn1Reader.readSet();
    while (setLen != 0) {
        VirgilByteArray keyValueAsn1 = asn1Reader.readData();
        VirgilAsn1Reader keyValueAsn1Reader(keyValueAsn1);

        (void)keyValueAsn1Reader.readSequence();
        VirgilByteArray key = keyValueAsn1Reader.readUTF8String();

        if (keyValueAsn1Reader.readContextTag(kCMS_IntegerValueTag) > 0) {
            intValues_[key] = keyValueAsn1Reader.readInteger();
        } else if (keyValueAsn1Reader.readContextTag(kCMS_StringValueTag) > 0) {
            stringValues_[key] = keyValueAsn1Reader.readUTF8String();
        } else if (keyValueAsn1Reader.readContextTag(kCMS_DataValueTag) > 0) {
            dataValues_[key] = keyValueAsn1Reader.readOctetString();
        } else {
            throw VirgilCryptoException(std::string("VirgilCustomParams: ") +
                    "Expected parameter 'val' is not defined or has unexpected type.");
        }
        setLen = setLen > keyValueAsn1.size() ? (setLen - keyValueAsn1.size()) : 0;
    }
}
