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

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/stream/VirgilStreamSigner.h>
using virgil::service::stream::VirgilStreamSigner;

#include <virgil/service/stream/VirgilStreamDataSource.h>
using virgil::service::stream::VirgilStreamDataSource;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

int print_usage(std::ostream& out, const char *programName) {
    out << "Usage: " << programName;
    out << " <data> <signer_cert_id> <private_key> <private_key_pwd> [<out_format>]" << std::endl;
    out << "    <data>            - [in]  file to be signed" << std::endl;
    out << "    <signer_cert_id>  - [in]  signer certificate isentifier" << std::endl;
    out << "    <private_key>     - [in]  private key file" << std::endl;
    out << "    <private_key_pwd> - [in]  private key password" << std::endl;
    out << "    <out_format>      - [in]  sign serialization format (asn1 | json)" << std::endl;
    return -1;
}

int main(int argc, char **argv) {
    // Parse arguments.
    const char *programName = argv[0];
    unsigned currArgPos = 0;

    // Check arguments num.
    if (argc < 5) {
        return print_usage(std::cerr, programName);
    }

    // Parse argument: data
    ++currArgPos;
    std::ifstream dataFile(argv[currArgPos], std::ios::in | std::ios::binary);
    if (!dataFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Parse argument: signer_cert_id
    ++currArgPos;
    VirgilByteArray signerCertificateId = virgil_byte_array_from_c_string(argv[currArgPos]);

    // Parse argument: private_key
    ++currArgPos;
    std::ifstream privateKeyFile(argv[currArgPos], std::ios::in);
    if (!privateKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray privateKey;
    std::copy(std::istreambuf_iterator<char>(privateKeyFile), std::istreambuf_iterator<char>(),
            std::back_inserter(privateKey));
    privateKeyFile.close();

    // Parse argument: private_key_pwd
    ++currArgPos;
    VirgilByteArray privateKeyPassword = virgil_byte_array_from_c_string(argv[currArgPos]);

    // Parse argument: format
    std::string format("json");
    if (++currArgPos < argc) {
        format = std::string(argv[currArgPos]);
    }

    // Create signer.
    VirgilStreamSigner signer;

    // Prepare input source.
    VirgilStreamDataSource dataSource(dataFile);

    // Sign data.
    VirgilSign sign = signer.sign(dataSource, signerCertificateId, privateKey, privateKeyPassword);

    // Marshal sign.
    VirgilByteArray signData;
    if (format == "asn1") {
        signData = sign.toAsn1();
    } else if (format == "json") {
        signData = sign.toJson();
    } else {
        std::cerr << "Unknown format: " << format << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Write data sign to file.
    std::copy(signData.begin(), signData.end(), std::ostreambuf_iterator<char>(std::cout));

    return 0;
}
