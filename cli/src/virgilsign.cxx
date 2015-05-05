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

#include <virgil/service/stream/VirgilStreamSigner.h>
using virgil::service::stream::VirgilStreamSigner;

#include <virgil/service/stream/VirgilStreamDataSource.h>
using virgil::service::stream::VirgilStreamDataSource;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <tclap/CmdLine.h>

#include "utils.h"

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN sign_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Decrypt data", ' ', virgil::cli::version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be signed. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Digest sign. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> formatArg("f", "format", "Output format: json | der (default).",
                false, "der", "arg");

        TCLAP::ValueArg<std::string> keyArg("k", "key", "Signer's private key.",
                true, "", "file");

        TCLAP::ValueArg<std::string> pwdArg("p", "pwd", "Signer's private key password.",
                false, "", "arg");

        TCLAP::ValueArg<std::string> certificateArg("c", "certificate", "Signer's certificate.",
                true, "", "arg");

        cmd.add(certificateArg);
        cmd.add(pwdArg);
        cmd.add(keyArg);
        cmd.add(formatArg);
        cmd.add(outArg);
        cmd.add(inArg);

        cmd.parse(argc, argv);

        // Prepare input.
        std::istream *inStream = &std::cin;
        std::ifstream inFile(inArg.getValue().c_str(), std::ios::in | std::ios::binary);
        if (inFile.good()) {
            inStream = &inFile;
        } else if (!inArg.getValue().empty()) {
            throw std::invalid_argument(std::string("can not read file: " + inArg.getValue()));
        }
        VirgilStreamDataSource dataSource(*inStream);

        // Prepare output.
        std::ostream *outStream = &std::cout;
        std::ofstream outFile(outArg.getValue().c_str(), std::ios::out | std::ios::binary);
        if (outFile.good()) {
            outStream = &outFile;
        } else if (!outArg.getValue().empty()) {
            throw std::invalid_argument(std::string("can not write file: " + outArg.getValue()));
        }

        // Read certificate
        VirgilCertificate certificate = virgil::cli::read_certificate(certificateArg.getValue());

        // Read private key
        std::ifstream keyFile(keyArg.getValue().c_str(), std::ios::in | std::ios::binary);
        if (!keyFile.good()) {
            throw std::invalid_argument(std::string("can not read private key: " + keyArg.getValue()));
        }
        VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(keyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(privateKey));
        VirgilByteArray privateKeyPassword = virgil::str2bytes(pwdArg.getValue());

        // Create signer.
        VirgilStreamSigner signer;

        // Sign data.
        VirgilSign sign = signer.sign(dataSource, certificate.id().certificateId(), privateKey, privateKeyPassword);

        // Marshal sign.
        VirgilByteArray signData;
        if (formatArg.getValue() == "der") {
            signData = sign.toAsn1();
        } else if (formatArg.getValue() == "json") {
            signData = sign.toJson();
        } else {
            throw std::invalid_argument(std::string("unknown --format: ") + formatArg.getValue());
        }

        // Write sign to the output.
        std::copy(signData.begin(), signData.end(), std::ostreambuf_iterator<char>(*outStream));

    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
