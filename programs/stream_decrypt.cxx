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
#include <string>
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
    out << "Usage: " << programName << " <enc_data> <enc_key> <private_key> <private_key_pwd>" << std::endl;
    out << "    <enc_data>        - [in] encrypted data file to be decrypted" << std::endl;
    out << "    <content_info>    - [in] encrypted data content info file" << std::endl;
    out << "    <private_key>     - [in] private key file" << std::endl;
    out << "    <private_key_pwd> - [in] private key password" << std::endl;
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

    // Parse argument: enc_data
    ++currArgPos;
    std::ifstream encryptedDataFile(argv[currArgPos], std::ios::in | std::ios::binary);
    if (!encryptedDataFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Parse argument: content_info
    ++currArgPos;
    std::ifstream contentInfoFile(argv[currArgPos], std::ios::in | std::ios::binary);
    if (!contentInfoFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray contentInfo;
    std::copy(std::istreambuf_iterator<char>(contentInfoFile), std::istreambuf_iterator<char>(),
            std::back_inserter(contentInfo));
    contentInfoFile.close();

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
    VirgilByteArray privateKeyPassword = VIRGIL_BYTE_ARRAY_FROM_C_STRING(argv[currArgPos]);

    // Create cipher.
    VirgilStreamCipher cipher;

    // Set encrypted data header.
    cipher.setContentInfo(contentInfo);

    // Prepare input source.
    VirgilStreamDataSource dataSource(encryptedDataFile);

    // Prepare output sink.
    VirgilStreamDataSink dataSink(std::cout);

    // Decrypt.
    cipher.decryptWithKey(dataSource, dataSink, privateKey, privateKeyPassword);

    return 0;
}
