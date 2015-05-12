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

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <tclap/CmdLine.h>

#include "version.h"

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN pub2cert_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Create certificate from the public key and identifiers.", ' ', cli_version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Public key. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Certificate. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> formatArg("f", "format", "Output format: json | der (default).",
                false, "der", "arg");

        TCLAP::ValueArg<std::string> accountIdArg("a", "account-id", "Account identifier.",
                false, "", "arg");

        TCLAP::ValueArg<std::string> certificateIdArg("c", "certificate-id", "Certificate identifier.",
                true, "", "arg");

        cmd.add(certificateIdArg);
        cmd.add(accountIdArg);
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

        // Prepare output.
        std::ostream *outStream = &std::cout;
        std::ofstream outFile(outArg.getValue().c_str(), std::ios::out | std::ios::binary);
        if (outFile.good()) {
            outStream = &outFile;
        } else if (!outArg.getValue().empty()) {
            throw std::invalid_argument(std::string("can not write file: " + outArg.getValue()));
        }

        // Read public key.
        VirgilByteArray publicKey;
        std::copy(std::istreambuf_iterator<char>(*inStream), std::istreambuf_iterator<char>(),
                std::back_inserter(publicKey));

        // Create certificate
        VirgilCertificate certificate(publicKey);
        certificate.id().setAccountId(virgil::str2bytes(accountIdArg.getValue()));
        certificate.id().setCertificateId(virgil::str2bytes(certificateIdArg.getValue()));

        // Marshal certificate
        VirgilByteArray certificateData;
        if (formatArg.getValue() == "der") {
            certificateData = certificate.toAsn1();
        } else if (formatArg.getValue() == "json") {
            certificateData = certificate.toJson();
        } else {
            throw std::invalid_argument(std::string("unknown --format: ") + formatArg.getValue());
        }

        // Output marshalled certificate
        std::copy(certificateData.begin(), certificateData.end(), std::ostreambuf_iterator<char>(*outStream));

        return EXIT_SUCCESS;
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
}
