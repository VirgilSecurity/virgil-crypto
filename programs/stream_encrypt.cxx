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

#include <virgil/service/VirgilStreamCipher.h>
using virgil::service::VirgilStreamCipher;

#include <virgil/service/stream/VirgilStreamDataSource.h>
using virgil::service::stream::VirgilStreamDataSource;

#include <virgil/service/stream/VirgilStreamDataSink.h>
using virgil::service::stream::VirgilStreamDataSink;

int print_usage(std::ostream& out) {
    out << "Usage: encrypt <public_key> <in> <out>" << std::endl;
    out << "    <in>         - [in]  file to be encrypted" << std::endl;
    out << "    <public_key> - [in]  public key file" << std::endl;
    out << "    <enc>        - [out] encrypted file" << std::endl;
    out << "    <enc_key>    - [out] encryption key file" << std::endl;
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        return print_usage(std::cerr);
    }

    // Parse arguments.
    std::ifstream inFile(argv[1], std::ios::in | std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[1] << std::endl;
        return print_usage(std::cerr);
    }

    std::ifstream publicKeyFile(argv[2], std::ios::in);
    if (!publicKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[2] << std::endl;
        return print_usage(std::cerr);
    }

    std::ofstream outFile(argv[3], std::ios::out | std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[3] << std::endl;
        return print_usage(std::cerr);
    }

    std::ofstream encryptionKeyFile(argv[4], std::ios::out | std::ios::binary);
    if (!encryptionKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[4] << std::endl;
        return print_usage(std::cerr);
    }
    // Create cipher.
    VirgilStreamCipher cipher;
    // Prepare input source.
    VirgilStreamDataSource dataSource(inFile);
    // Prepare output sink.
    VirgilStreamDataSink dataSink(outFile);
    // Read public key.
    VirgilByteArray publicKey;
    std::copy(std::istreambuf_iterator<char>(publicKeyFile), std::istreambuf_iterator<char>(),
            std::back_inserter(publicKey));
    // Encrypt stream.
    VirgilByteArray encryptionKey = cipher.encrypt(dataSource, dataSink, publicKey);
    // Write encryption key to file.
    std::copy(encryptionKey.begin(), encryptionKey.end(), std::ostreambuf_iterator<char>(encryptionKeyFile));

    return 0;
}
