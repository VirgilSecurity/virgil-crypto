/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#include <virgil/crypto/VirgilByteArrayUtils.h>

#include <string>
#include <vector>
#include <algorithm>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <rapidjson/document.h>
#include <rapidjson/reader.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::VirgilByteArrayUtils;

using virgil::crypto::foundation::asn1::VirgilAsn1Writer;


typedef rapidjson::Value json;

/**
 * @brief Write json value as ASN.1 structure.
 * @return Number of written bytes to ASN.1.
 */
static size_t asn1_write_json_value(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key = "");

/**
 * @brief Write json object as ASN.1 structure.
 * @return Number of written bytes to ASN.1.
 */
static size_t asn1_write_json_object(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key = "");

/**
 * @brief Write json array as ASN.1 structure.
 * @return Number of written bytes to ASN.1.
 */
static size_t asn1_write_json_array(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key = "");

/**
 * @brief Write json primitive (string, number, boolean, or nul) as ASN.1 structure.
 * @return Number of written bytes to ASN.1.
 */
static size_t asn1_write_json_primitive(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key = "");

/**
 * @brief JSON to ASN.1 mapping
 */
VirgilByteArray VirgilByteArrayUtils::jsonToBytes(const std::string& jsonString) {
    try {
        rapidjson::Document jsonObj;
        jsonObj.Parse(jsonString.c_str());
        VirgilAsn1Writer asn1Writer;
        (void)asn1_write_json_value(asn1Writer, jsonObj);
        return asn1Writer.finish();
    } catch (const std::exception& exception) {
        throw VirgilCryptoException(exception.what());
    }
}

VirgilByteArray VirgilByteArrayUtils::stringToBytes(const std::string& str) {
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(str.data(), str.size());
}

std::string VirgilByteArrayUtils::bytesToString(const VirgilByteArray& array) {
    return std::string(reinterpret_cast<const char *>(array.data()), array.size());
}

VirgilByteArray VirgilByteArrayUtils::hexToBytes(const std::string& hexStr) {
    VirgilByteArray result;
    std::istringstream istr(hexStr);
    char hexChars[3] = {0x00};
    while (istr.read(hexChars, 2)) {
        int byte = 0;
        std::istringstream(hexChars) >> std::hex >> byte;
        result.push_back((unsigned char)byte);
    }
    return result;
}

std::string VirgilByteArrayUtils::bytesToHex(const VirgilByteArray& array, bool formatted) {
    std::ostringstream hexStream;
    hexStream << std::setfill('0');
    for(size_t i = 0; i < array.size(); ++i) {
        hexStream << std::hex << std::setw(2) << (int)array[i];
        if (formatted) {
            hexStream << (((i + 1) % 16 == 0) ? "\n" : " ");
        }
    }
    return hexStream.str();
}

void VirgilByteArrayUtils::zeroize(VirgilByteArray& array) {
    virgil::crypto::bytes_zeroize(array);
}

size_t asn1_write_json_value(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (json.IsObject()) {
        return asn1_write_json_object(asn1Writer, json, key);
    }
    if (json.IsArray()) {
        return asn1_write_json_array(asn1Writer, json, key);
    }
    return asn1_write_json_primitive(asn1Writer, json, key);
}

static bool compare_c_str(const char * a, const char * b) {
    return std::strcmp(a, b) < 0;
}

size_t asn1_write_json_object(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (!json.IsObject()) {
        throw std::logic_error("Json: Expected object type.");
    }
    size_t len = 0;
    // Get object keys
    std::vector<const char *> keys;
    for (json::ConstMemberIterator it = json.MemberBegin(); it != json.MemberEnd(); ++it) {
        keys.push_back(it->name.GetString());
    }
    // Sort object keys
    std::sort(keys.begin(), keys.end(), compare_c_str);
    // Process object values
    for (std::vector<const char *>::const_reverse_iterator it = keys.rbegin(); it != keys.rend(); ++it) {
        len += asn1_write_json_value(asn1Writer, json[*it], *it);
    }
    len += asn1Writer.writeSequence(len);
    if (!key.empty()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(key));
        len += asn1Writer.writeSequence(len);
    }
    return len;
}

size_t asn1_write_json_array(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (!json.IsArray()) {
        throw std::logic_error("Json: Expected array type.");
    }
    size_t len = 0;
    std::reverse_iterator<json::ConstValueIterator> jsonCurr(json.End());
    std::reverse_iterator<json::ConstValueIterator> jsonEnd(json.Begin());
    for (; jsonCurr != jsonEnd; ++jsonCurr) {
        len += asn1_write_json_value(asn1Writer, *jsonCurr);
    }
    len += asn1Writer.writeSequence(len);
    if (!key.empty()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(key));
        len += asn1Writer.writeSequence(len);
    }
    return len;
}

size_t asn1_write_json_primitive(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (json.IsObject() || json.IsArray()) {
        throw std::logic_error("Json: Expected primitive type.");
    }
    size_t len = 0;
    if (json.IsInt()) {
        len += asn1Writer.writeInteger(json.GetInt());
    } else if (json.IsDouble()) {
        throw VirgilCryptoException("VirgilByteArrayUtils: not supported float values in JSON.");
    } else if (json.IsBool()) {
        len += asn1Writer.writeBool(json.GetBool());
    } else if (json.IsString()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(json.GetString()));
    } else if (json.IsNull()) {
        len += asn1Writer.writeNull();
    } else {
        throw std::logic_error("Json: Unknown object type.");
    }
    if (!key.empty()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(key));
        len += asn1Writer.writeSequence(len);
    }
    return len;
}
