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

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <tclap/CmdLine.h>

#include "utils.h"

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN certinfo_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Output certificate details.", ' ', virgil::cli::version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Certificate. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Certificate information. If omitted stdout is used.",
                false, "", "file");

        TCLAP::SwitchArg accountIdArg("a", "account-id", "Output account identifier.",
                false);

        TCLAP::SwitchArg certificateIdArg("c", "certificate-id", "Output certificate identifier.",
                false);

        TCLAP::SwitchArg publicKeyArg("p", "public-key", "Output public key.",
                false);


        cmd.add(publicKeyArg);
        cmd.add(certificateIdArg);
        cmd.add(accountIdArg);
        cmd.add(outArg);
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

        // Prepare output.
        std::ostream *outStream = &std::cout;
        std::ofstream outFile(outArg.getValue(), std::ios::out | std::ios::binary);
        if (outFile.good()) {
            outStream = &outFile;
        } else if (!outArg.getValue().empty()) {
            throw std::invalid_argument(std::string("can not write file: " + outArg.getValue()));
        }

        // Read certificate
        VirgilCertificate certificate = virgil::cli::read_certificate(*inStream);

        // Output certificate details
        bool showAll = virgil::cli::xor3(accountIdArg.getValue(), certificateIdArg.getValue(), publicKeyArg.getValue());
        bool showMultiple = showAll ||
                (accountIdArg.getValue() && certificateIdArg.getValue()) ||
                (certificateIdArg.getValue() && publicKeyArg.getValue()) ||
                (accountIdArg.getValue() && publicKeyArg.getValue());

        if (accountIdArg.getValue() || showAll) {
            if (showMultiple) {
                *outStream << "account id: ";
            }
            *outStream << virgil::bytes2str(certificate.id().accountId()) << std::endl;
        }

        if (certificateIdArg.getValue() || showAll) {
            if (showMultiple) {
                *outStream << "certificate id: ";
            }
            *outStream << virgil::bytes2str(certificate.id().certificateId()) << std::endl;
        }

        if (publicKeyArg.getValue() || showAll) {
            VirgilByteArray publicKey = certificate.publicKey();
            if (showMultiple) {
                *outStream << "public key:" << std::endl;
            }
            if (virgil::cli::is_asn1(publicKey)) {
                *outStream << virgil::bytes2hex(publicKey, true) << std::endl;
            } else {
                *outStream << virgil::bytes2str(publicKey);
            }
        }
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
