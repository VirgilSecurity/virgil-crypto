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

#include <virgil/service/data/VirgilJsonCompatible.h>
using virgil::service::data::VirgilJsonCompatible;

#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <string>
#include <sstream>

VirgilByteArray VirgilJsonCompatible::toJson() const {
    Json::Value childValue(Json::objectValue);
    Json::Value rootObject = jsonWrite(childValue);
    return virgil_byte_array_from_std_string(Json::StyledWriter().write(rootObject));
}

void VirgilJsonCompatible::fromJson(const VirgilByteArray& json) {
    Json::Reader reader(Json::Features::strictMode());
    Json::Value rootObject;
    if (!reader.parse(virgil_byte_array_to_std_string(json), rootObject)) {
        throw VirgilException(reader.getFormattedErrorMessages());
    }
    jsonRead(rootObject);
}

void VirgilJsonCompatible::jsonCheckParamNotEmpty(const VirgilByteArray& param,  const char *paramName) const {
    if (param.empty()) {
        std::ostringstream ostr;
        ostr << "VirgilJsonCompatible: ";
        ostr << "Required JSON parameter is not specified.";
        if (paramName != 0) {
            ostr << " Parameter name: " << paramName << ".";
        }
        throw VirgilException(ostr.str());
    }
}

static std::string jsonValueTypeToString_(Json::ValueType jsonType) {
    switch (jsonType) {
        case Json::intValue:
            return "Integer";
        case Json::uintValue:
            return "Unsigned";
        case Json::realValue:
            return "Real";
        case Json::stringValue:
            return "String";
        case Json::booleanValue:
            return "Boolean";
        case Json::arrayValue:
            return "Array";
        case Json::objectValue:
            return "Object";
        case Json::nullValue:
        default:
            return "Null";
    }
}

Json::Value VirgilJsonCompatible::jsonGetValue(const Json::Value& json, const char *key, Json::ValueType valueType) {
    Json::Value value = json[key];
    if (value.type() != valueType) {
        throw VirgilException(std::string("VirgilJsonCompatible: ") +
                "Expected Json " + jsonValueTypeToString_(valueType) + " value under key: '" + key +
                "', but found " + jsonValueTypeToString_(value.type()) + " value.");
    }
    return value;
}

std::string VirgilJsonCompatible::jsonGetString(const Json::Value& json, const char *key) {
    return jsonGetValue(json, key, Json::stringValue).asString();
}

VirgilByteArray VirgilJsonCompatible::jsonGetStringAsByteArray(const Json::Value& json, const char *key) {
    return virgil_byte_array_from_std_string(jsonGetString(json, key));
}

Json::Value VirgilJsonCompatible::jsonRawDataToValue(const VirgilByteArray& data) {
    return Json::Value(VirgilBase64::encode(data));
}

VirgilByteArray VirgilJsonCompatible::jsonRawDataFromValue(const Json::Value& json) {
    return VirgilBase64::decode(json.asString());
}

Json::Value VirgilJsonCompatible::jsonMergeObjects(const Json::Value& obj1, const Json::Value& obj2) {
    if (!obj1.isObject() || !obj2.isObject()) {
        throw VirgilException(std::string("VirgilJsonCompatible:") +
                "Attempt to merge non object JSON values.");
    }
    Json::Value result(Json::objectValue);
    for (Json::Value::const_iterator it = obj1.begin(); it != obj1.end(); ++it) {
        result[it.memberName()] = *it;
    }
    for (Json::Value::const_iterator it = obj2.begin(); it != obj2.end(); ++it) {
        result[it.memberName()] = *it;
    }
    return result;
}
