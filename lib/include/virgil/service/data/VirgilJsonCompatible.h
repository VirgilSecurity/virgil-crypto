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

#ifndef VIRGIL_SERVICE_DATA_VIRGIL_JSON_COMPATIBLE_H
#define VIRGIL_SERVICE_DATA_VIRGIL_JSON_COMPATIBLE_H

#include <virgil/crypto/asn1/VirgilAsn1Compatible.h>
using virgil::crypto::asn1::VirgilAsn1Compatible;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace Json {
    class Value;
}

namespace virgil { namespace service { namespace data {

/**
 * @brief This class provides interface that allow to save and restore object state in the JSON object.
 */
class VirgilJsonCompatible : public VirgilAsn1Compatible {
public:
    /**
     * @brief Save object state to the JSON object.
     */
    VirgilByteArray toJson() const;
    /**
     * @brief Restore object state from the JSON object.
     */
    void fromJson(const VirgilByteArray& json);
    /**
     * @brief Polymorphic destructor.
     */
     virtual ~VirgilJsonCompatible() throw() {}
    /**
     * @brief Write object state to the writer.
     * @param childValue - JSON value written by the child.
     * @return Written JSON value.
     */
    virtual Json::Value jsonWrite(Json::Value& childValue) const = 0;
    /**
     * @brief Read object state from the reader.
     * @param parentValue - parent JSON object, SHOULD be passed to the parent 'jsonRead()' method.
     * @return Read JSON value, that SHOULD be used by children.
     */
    virtual Json::Value jsonRead(const Json::Value& parentValue) = 0;
protected:
    /**
     * @brief If given parameter is empty exception will be thrown.
     * @throw virgil::VirgilException.
     */
    virtual void jsonCheckParamNotEmpty(const VirgilByteArray& param, const char *paramName = 0) const;
    /**
     * @name JSON utility methods
     */
    ///@{
    /**
     * @brief Read JSON string value under given key.
     * @throw VirgilException if value not found or value is not a string.
     */
    static std::string jsonGetString(const Json::Value& json, const char *key);
    /**
     * @brief Read JSON string value under given key and return it as VirgilByteArray.
     * @throw VirgilException if value not found or value is not a string.
     */
    static VirgilByteArray jsonGetStringAsByteArray(const Json::Value& json, const char *key);
    /**
     * @brief Write byte array to JSON.
     */
    static Json::Value jsonRawDataToValue(const VirgilByteArray& data);
    /**
     * @brief Read byte array from JSON value.
     */
    static VirgilByteArray jsonRawDataFromValue(const Json::Value& json);
    /**
     * @brief Merge two JSON values of type: object.
     */
    static Json::Value jsonMergeObjects(const Json::Value& obj1, const Json::Value& obj2);
    ///@}
};

}}}

#endif /* VIRGIL_SERVICE_DATA_VIRGIL_JSON_COMPATIBLE_H */
