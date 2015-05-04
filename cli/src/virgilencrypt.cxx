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

#include <virgil/service/stream/VirgilStreamCipher.h>
using virgil::service::stream::VirgilStreamCipher;

#include <virgil/service/stream/VirgilStreamDataSource.h>
using virgil::service::stream::VirgilStreamDataSource;

#include <virgil/service/stream/VirgilStreamDataSink.h>
using virgil::service::stream::VirgilStreamDataSink;

#include <tclap/CmdLine.h>

#include "utils.h"

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN encrypt_main
#endif

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Encrypt data", ' ', virgil::cli::version());

        TCLAP::ValueArg<std::string> inArg("i", "in", "Data to be encrypted. If omitted stdin is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Encrypted data. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> contentInfoArg("c", "content-info",
                "Content info. If omitted - becomes a part of the encrypted data.",
                false, "", "file");

        TCLAP::MultiArg<std::string> recipientsConfigArg("r", "recipients",
                "File that contains information about recipients. Each line can be either empty line, "
                "or comment line, or path to the recipient's certificate, or recipient's password.",
                false, "file");

        TCLAP::UnlabeledMultiArg<std::string> recipientsArg("recipient",
                "Either path to the recipient's certificate, or the recipient's password.",
                false, "recipient", true);


        cmd.add(recipientsArg);
        cmd.add(recipientsConfigArg);
        cmd.add(contentInfoArg);
        cmd.add(outArg);
        cmd.add(inArg);

        cmd.parse(argc, argv);

        // Create cipher.
        VirgilStreamCipher cipher;

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
        VirgilStreamDataSink dataSink(*outStream);

        // Add recipients
        virgil::cli::add_recipients_config(cipher, recipientsConfigArg.getValue());
        virgil::cli::add_recipients(cipher, recipientsArg.getValue());

        // Define whether embed content info or not
        bool embedContentInfo = contentInfoArg.getValue().empty();

        // Encrypt.
        cipher.encrypt(dataSource, dataSink, embedContentInfo);

        // Write content info to file if it was not embedded
        if (!embedContentInfo) {
            std::ofstream contentInfoFile(contentInfoArg.getValue().c_str(), std::ios::out | std::ios::binary);
            if (contentInfoFile.good()) {
                VirgilByteArray contentInfo = cipher.getContentInfo();
                std::copy(contentInfo.begin(), contentInfo.end(), std::ostreambuf_iterator<char>(contentInfoFile));
            } else {
                throw std::invalid_argument(std::string("can not write file: " + contentInfoArg.getValue()));
            }
        }
        return EXIT_SUCCESS;
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
}
