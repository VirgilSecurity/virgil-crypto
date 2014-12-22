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
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/VirgilSigner.h>
using virgil::service::VirgilSigner;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/marshalling/VirgilAsn1DataMarshaller.h>
using virgil::service::data::marshalling::VirgilAsn1DataMarshaller;

int print_usage(std::ostream& out, const char *programName) {
    out << "Usage: " << programName << " <data> <sign> <public_key>" << std::endl;
    out << "    <data>       - [in] data to be verified" << std::endl;
    out << "    <sign>       - [in] data sign file" << std::endl;
    out << "    <public_key> - [in] public key file" << std::endl;
    return -1;
}

int main(int argc, char **argv) {
    // Parse arguments.
    const char *programName = argv[0];
    unsigned currArgPos = 0;

    // Check arguments num.
    if (argc < 4) {
        return print_usage(std::cerr, programName);
    }

    // Parse argument: data
    ++currArgPos;
    VirgilByteArray data = VIRGIL_BYTE_ARRAY_FROM_STD_STRING(std::string(argv[currArgPos]));

    // Parse argument: sign
    ++currArgPos;
    std::ifstream signFile(argv[currArgPos], std::ios::in | std::ios::binary);
    if (!signFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray signData;
    std::copy(std::istreambuf_iterator<char>(signFile), std::istreambuf_iterator<char>(),
            std::back_inserter(signData));
    signFile.close();

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

    // Create signer.
    VirgilSigner signer;

    VirgilSign *sign = (VirgilSign *)0;
    try {
        // Demarshal sign.
        VirgilAsn1DataMarshaller marshaller;
        sign = marshaller.demarshalSign(signData);

        // Verify data.
        bool verified = signer.verify(data, *sign, publicKey);
        std::cout << "Verified: " << (verified ? "YES" : "NO") << std::endl;

        // Dispose resources.
        delete sign;
    } catch (const std::exception& exception) {
        std::cerr << "Verification failed due to exception: " << exception.what() << std::endl;
        if (sign) {
            delete sign;
        }
    }

    return 0;
}
