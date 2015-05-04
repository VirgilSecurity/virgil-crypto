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

#include <tclap/CmdLine.h>

#include "utils.h"

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN verify_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Decrypt data", ' ', virgil::cli::version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be signed. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out",
                "Verification result: success | failure. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> signArg("s", "sign", "Digest sign.",
                true, "", "file");

        TCLAP::ValueArg<std::string> certificateArg("c", "certificate", "Signer's certificate.",
                true, "", "file");


        cmd.add(certificateArg);
        cmd.add(signArg);
        cmd.add(inArg);

        cmd.parse(argc, argv);

        // Prepare input.
        std::istream *inStream = &std::cin;
        std::ifstream inFile(inArg.getValue(), std::ios::in | std::ios::binary);
        if (inFile.good()) {
            inStream = &inFile;
        } else if (!inArg.getValue().empty()) {
            throw std::invalid_argument(std::string("can not read file: " + inArg.getValue()));
        }
        VirgilStreamDataSource dataSource(*inStream);

        // Prepare output.
        std::ostream *outStream = &std::cout;
        std::ofstream outFile(outArg.getValue(), std::ios::out | std::ios::binary);
        if (outFile.good()) {
            outStream = &outFile;
        } else if (!outArg.getValue().empty()) {
            throw std::invalid_argument(std::string("can not write file: " + outArg.getValue()));
        }

        // Read sign
        VirgilSign sign = virgil::cli::read_sign(signArg.getValue());

        // Read certificate
        VirgilCertificate certificate = virgil::cli::read_certificate(certificateArg.getValue());

        // Create signer.
        VirgilStreamSigner signer;

        // Verify data.
        bool verified = signer.verify(dataSource, sign, certificate.publicKey());
        if (verified) {
            *outStream << "success" << std::endl;
            return EXIT_SUCCESS;
        } else {
            *outStream << "failure" << std::endl;
            return EXIT_FAILURE;
        }
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
}
