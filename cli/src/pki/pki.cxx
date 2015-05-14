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

#include <cli/pki.h>

#include <cstddef>
#include <stdexcept>

#include <curl/curl.h>
#include <json/json.h>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;

#define MAKE_URL(base, path) (base path)

static int pki_callback(char *data, size_t size, size_t nmemb, std::string *buffer_in) {
    // Is there anything in the buffer?
    if (buffer_in != NULL) {
        // Append the data to the buffer
        buffer_in->append(data, size * nmemb);
        return size * nmemb;
    }
    return 0;
}

static std::string pki_post(const std::string& url, const std::string& json) {
    CURL *curl = NULL;
    CURLcode result = CURLE_OK;
    struct curl_slist *headers = NULL;
    std::string response;

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl) {
        /* set content type */
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        /* Set the URL */
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, json.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pki_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)(&response));

        /* Perform the request, result will get the return code */
        result = curl_easy_perform(curl);

        /* free headers */
        curl_slist_free_all(headers);

        /* cleanup curl handle */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    /* Check for errors */
    if (result == CURLE_OK) {
        return response;
    } else {
        throw VirgilException(std::string("cURL failed with error: ") + curl_easy_strerror(result));
    }
}

VirgilCertificate
virgil::pki_get_certificate(const std::string& userIdType, const std::string& userId) {
    // Create request
    Json::Value payload;
    payload[userIdType] = userId;
    // Perform request
    std::string response = pki_post(MAKE_URL(VIRGIL_PKI_URL_BASE, "objects/account/actions/search"),
            Json::FastWriter().write(payload));
    // Parse response
    Json::Reader reader(Json::Features::strictMode());
    Json::Value responseObject;
    if (!reader.parse(response, responseObject)) {
        throw VirgilException(reader.getFormattedErrorMessages());
    }
    const Json::Value& certificateObject = responseObject[0]["public_keys"][0];
    const Json::Value& idObject = certificateObject["id"]["public_key_id"];
    const Json::Value& publicKeyObject = certificateObject["public_key"];

    if (idObject.isString() && publicKeyObject.isString()) {
        VirgilCertificate certificate(VirgilBase64::decode(publicKeyObject.asString()));
        certificate.id().setCertificateId(virgil::str2bytes(idObject.asString()));
        return certificate;
    } else {
        throw VirgilException(std::string("certificate for recipient '") + userId +
                "' of type '" + userIdType + "' not found");
    }
}

VirgilCertificate
virgil::pki_create_user(const VirgilByteArray& publicKey, const std::map<std::string, std::string>& ids) {
    // Create request
    Json::Value payload;
    payload["public_key"] = VirgilBase64::encode(publicKey);
    Json::Value userData(Json::arrayValue);
    for (std::map<std::string, std::string>::const_iterator id = ids.begin(); id != ids.end(); ++id) {
        Json::Value data(Json::objectValue);
        data["class"] = "user_id";
        data["type"] = id->first;
        data["value"] = id->second;
        userData.append(data);
    }
    payload["user_data"] = userData;
    // Perform request
    std::string response = pki_post(MAKE_URL(VIRGIL_PKI_URL_BASE, "objects/public-key"),
            Json::FastWriter().write(payload));
    // Parse response
    Json::Reader reader(Json::Features::strictMode());
    Json::Value responseObject;
    if (!reader.parse(response, responseObject)) {
        throw VirgilException(reader.getFormattedErrorMessages());
    }
    const Json::Value& accountIdObject = responseObject["id"]["account_id"];
    const Json::Value& publicKeyIdObject = responseObject["id"]["public_key_id"];

    if (accountIdObject.isString() && publicKeyIdObject.isString()) {
        VirgilCertificate certificate(publicKey);
        certificate.id().setAccountId(virgil::str2bytes(accountIdObject.asString()));
        certificate.id().setCertificateId(virgil::str2bytes(publicKeyIdObject.asString()));
        return certificate;
    } else {
        throw VirgilException(std::string("Unexpected response format:\n") + responseObject.toStyledString());
    }
}

