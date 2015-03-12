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

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/stream/VirgilStreamCipher.h>
using virgil::service::stream::VirgilStreamCipher;

#include <virgil/service/stream/VirgilStreamDataSource.h>
using virgil::service::stream::VirgilStreamDataSource;

#include <virgil/service/stream/VirgilStreamDataSink.h>
using virgil::service::stream::VirgilStreamDataSink;

int print_usage(std::ostream& out, const char *programName) {
    out << "Usage: " << programName << " <data> <cert_id> <public_key> <enc_data> <enc_key>" << std::endl;
    out << "    <data>         - [in]  file to be encrypted" << std::endl;
    out << "    <cert_id>      - [in]  public key certificate identifier" << std::endl;
    out << "    <public_key>   - [in]  public key file" << std::endl;
    out << "    <enc_data>     - [out] encrypted data file" << std::endl;
    out << "    <content_info> - [out] encrypted data content info file" << std::endl;
    return -1;
}

int main(int argc, char **argv) {
    // Parse arguments.
    const char *programName = argv[0];
    unsigned currArgPos = 0;

    // Check arguments num.
    if (argc < 6) {
        return print_usage(std::cerr, programName);
    }

    // Parse argument: data
    ++currArgPos;
    std::ifstream dataFile(argv[currArgPos], std::ios::in | std::ios::binary);
    if (!dataFile.is_open()) {
        std::cerr << "Unable to open file: " << argv[currArgPos] <<  std::endl;
        return print_usage(std::cerr, programName);
    }

    // Parse argument: cert_id
    ++currArgPos;
    VirgilByteArray certId = virgil_byte_array_from_c_string(argv[currArgPos]);

    // Parse argument: public_key
    ++currArgPos;
    std::ifstream publicKeyFile(argv[currArgPos], std::ios::in);
    if (!publicKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray publicKey;
    std::copy(std::istreambuf_iterator<char>(publicKeyFile), std::istreambuf_iterator<char>(),
            std::back_inserter(publicKey));
    publicKeyFile.close();

    // Parse argument: enc_data
    ++currArgPos;
    std::ofstream encryptedDataFile(argv[currArgPos], std::ios::out | std::ios::binary);
    if (!encryptedDataFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Parse argument: content_info
    ++currArgPos;
    std::ofstream contentInfoFile(argv[currArgPos], std::ios::out | std::ios::binary);
    if (!contentInfoFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Create cipher.
    VirgilStreamCipher cipher;

    // Add recipients
    cipher.addKeyRecipient(certId, publicKey);

    // Prepare input source.
    VirgilStreamDataSource dataSource(dataFile);

    // Prepare output sink.
    VirgilStreamDataSink dataSink(encryptedDataFile);

    // Encrypt stream.
    cipher.encrypt(dataSource, dataSink);

    // Write content info to file.
    VirgilByteArray contentInfo = cipher.getContentInfo();
    std::copy(contentInfo.begin(), contentInfo.end(), std::ostreambuf_iterator<char>(contentInfoFile));

    return 0;
}
