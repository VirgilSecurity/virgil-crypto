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
#include <algorithm>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <json.hpp>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::VirgilByteArrayUtils;

using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

using json = nlohmann::json;

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
        json jsonObj = json::parse(jsonString);
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
    std::fill(array.begin(), array.end(), 0);
}

size_t asn1_write_json_value(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (json.is_object()) {
        return asn1_write_json_object(asn1Writer, json, key);
    }
    if (json.is_array()) {
        return asn1_write_json_array(asn1Writer, json, key);
    }
    if (json.is_primitive()) {
        return asn1_write_json_primitive(asn1Writer, json, key);
    }
    throw std::logic_error("Json: Unknown object type.");
}

size_t asn1_write_json_object(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (!json.is_object()) {
        throw std::logic_error("Json: Expected object type.");
    }
    size_t len = 0;
    json::object_t jsonMap = json;
    for (json::object_t::const_reverse_iterator it = jsonMap.rbegin(); it != jsonMap.rend(); ++it) {
        len += asn1_write_json_value(asn1Writer, it->second, it->first);
    }
    len += asn1Writer.writeSequence(len);
    if (!key.empty()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(key));
        len += asn1Writer.writeSequence(len);
    }
    return len;
}

size_t asn1_write_json_array(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (!json.is_array()) {
        throw std::logic_error("Json: Expected array type.");
    }
    size_t len = 0;
    for (json::const_reverse_iterator it = json.rbegin(); it != json.rend(); ++it) {
        len += asn1_write_json_value(asn1Writer, *it);
    }
    len += asn1Writer.writeSequence(len);
    if (!key.empty()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(key));
        len += asn1Writer.writeSequence(len);
    }
    return len;
}

size_t asn1_write_json_primitive(VirgilAsn1Writer& asn1Writer, const json& json, const std::string& key) {
    if (!json.is_primitive()) {
        throw std::logic_error("Json: Expected primitive type.");
    }
    size_t len = 0;
    if (json.is_number_integer()) {
        len += asn1Writer.writeInteger(json);
    } else if (json.is_number_float()) {
        throw VirgilCryptoException("VirgilByteArrayUtils: not supported float values in JSON.");
    } else if (json.is_boolean()) {
        len += asn1Writer.writeBool(json);
    } else if (json.is_string()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(json));
    } else if (json.is_null()) {
        len += asn1Writer.writeNull();
    }
    if (!key.empty()) {
        len += asn1Writer.writeUTF8String(VirgilByteArrayUtils::stringToBytes(key));
        len += asn1Writer.writeSequence(len);
    }
    return len;
}
