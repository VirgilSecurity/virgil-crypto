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

#include <virgil/service/VirgilCipher.h>
using virgil::service::VirgilCipher;

int print_usage(std::ostream& out, const char *programName) {
    out << "Usage: " << programName << " <enc_data> <pwd>" << std::endl;
    out << "    <enc_data> - [in] encrypted data file to be decrypted" << std::endl;
    out << "    <pwd>      - [in] password" << std::endl;
    return -1;
}

int main(int argc, char **argv) {
    // Parse arguments.
    const char *programName = argv[0];
    unsigned currArgPos = 0;

    // Check arguments num.
    if (argc < 3) {
        return print_usage(std::cerr, programName);
    }

    // Parse argument: enc_data
    ++currArgPos;
    std::ifstream encryptedDataFile(argv[currArgPos], std::ios::in | std::ios::binary);
    if (!encryptedDataFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray encryptedData;
    std::copy(std::istreambuf_iterator<char>(encryptedDataFile), std::istreambuf_iterator<char>(),
            std::back_inserter(encryptedData));
    encryptedDataFile.close();

    // Parse argument: pwd
    ++currArgPos;
    VirgilByteArray password = VIRGIL_BYTE_ARRAY_FROM_STD_STRING(std::string(argv[currArgPos]));

    // Create cipher.
    VirgilCipher cipher;

    // Decrypt.
    VirgilByteArray decryptedData = cipher.decryptWithPassword(encryptedData, password);

    // Print decrypted data.
    std::cout << VIRGIL_BYTE_ARRAY_TO_STD_STRING(decryptedData) << std::endl;

    return 0;
}
