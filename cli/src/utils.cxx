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

#include "utils.h"

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>

const char * virgil::cli::version() {
    return "@CPP_CLI_VERSION@, virgil library  version: @VIRGIL_VERSION@";
}

std::string virgil::cli::basename(const std::string& path) {
    size_t found = path.find_last_of("/\\");
    if (found != std::string::npos) {
        return path.substr(found + 1);
    } else {
        return path;
    }
}

bool virgil::cli::xor3(bool a, bool b, bool c) {
    return (a && b && c) || (!a && !b && !c);
}

bool virgil::cli::is_asn1(const VirgilByteArray& data) {
    return data.size() > 0 && data[0] == 0x30;
}

VirgilCertificate virgil::cli::read_certificate(const std::string& fileName) {
    std::ifstream certificateFile(fileName, std::ios::in | std::ios::binary);
    return virgil::cli::read_certificate(certificateFile, fileName);
}

VirgilCertificate virgil::cli::read_certificate(std::istream& file, const std::string& fileName) {
    if (!file.good()) {
        throw std::invalid_argument(std::string("can not read recipient's certificate from file: " + fileName));
    }
    VirgilByteArray certificateData;
    std::copy(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>(),
            std::back_inserter(certificateData));
    if (certificateData.empty()) {
        throw std::invalid_argument(std::string("recipient's certificate file is empty: ") + fileName);
    }
    VirgilCertificate certificate;
    if (virgil::cli::is_asn1(certificateData)) {
        // ASN.1 format
        certificate.fromAsn1(certificateData);
    } else {
        // JSON format
        certificate.fromJson(certificateData);
    }
    return certificate;
}

VirgilSign virgil::cli::read_sign(const std::string& fileName) {
    std::ifstream signFile(fileName, std::ios::in | std::ios::binary);
    return virgil::cli::read_sign(signFile, fileName);
}

VirgilSign virgil::cli::read_sign(std::istream& file, const std::string& fileName) {
    if (!file.good()) {
        throw std::invalid_argument(std::string("can not read sign from file: " + fileName));
    }
    VirgilByteArray signData;
    std::copy(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>(),
            std::back_inserter(signData));
    if (signData.empty()) {
        throw std::invalid_argument(std::string("sign file is empty: ") + fileName);
    }
    VirgilSign sign;
    if (virgil::cli::is_asn1(signData)) {
        // ASN.1 format
        sign.fromAsn1(signData);
    } else {
        // JSON format
        sign.fromJson(signData);
    }
    return sign;
}

size_t virgil::cli::add_recipients_config(VirgilCipherBase& cipher, const std::vector<std::string>& recipientsConfig) {
    size_t addedRecipientsCount = 0;
    for (std::vector<std::string>::const_iterator it = recipientsConfig.begin();
            it != recipientsConfig.end(); ++it) {
        std::ifstream configFile(*it);
        if (!configFile.good()) {
            std::cerr << "Warning: " << "can not read recipient config file: " << *it << std::endl;
            continue;
        }
        // Else
        std::string recipient;
        while (configFile >> std::ws && std::getline(configFile, recipient)) {
            if (!recipient.empty() && recipient[0] != '#') {
                virgil::cli::add_recipient(cipher, recipient);
                ++addedRecipientsCount;
            }
        }
    }
    return addedRecipientsCount;
}

size_t virgil::cli::add_recipients(VirgilCipherBase& cipher, const std::vector<std::string>& recipients) {
    for (std::vector<std::string>::const_iterator it = recipients.begin();
            it != recipients.end(); ++it) {
        virgil::cli::add_recipient(cipher, *it);
    }
    return recipients.size();
}

void virgil::cli::add_recipient(VirgilCipherBase& cipher, const std::string& recipient) {
    std::ifstream certificateFile(recipient, std::ios::in | std::ios::binary);
    if (certificateFile.good()) {
        VirgilCertificate certificate = virgil::cli::read_certificate(certificateFile);
        cipher.addKeyRecipient(certificate.id().certificateId(), certificate.publicKey());
    } else {
        cipher.addPasswordRecipient(virgil::str2bytes(recipient));
    }
}
