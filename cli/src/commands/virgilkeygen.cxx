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

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>
#include <map>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/VirgilKeyPairGenerator.h>
using virgil::crypto::VirgilKeyPairGenerator;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

#include <tclap/CmdLine.h>

#include <cli/version.h>

#ifdef SPLIT_CLI
    #define MAIN main
#else
    #define MAIN keygen_main
#endif

static VirgilKeyPairGenerator::ECKeyGroup ec_key_group_from_param(const std::string& param) {
    std::map<std::string, VirgilKeyPairGenerator::ECKeyGroup> ecKeyGroup;
    ecKeyGroup["secp192r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192R1;
    ecKeyGroup["secp224r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224R1;
    ecKeyGroup["secp256r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256R1;
    ecKeyGroup["secp384r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP384R1;
    ecKeyGroup["secp521r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP521R1;
    ecKeyGroup["bp256r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_BP256R1;
    ecKeyGroup["bp384r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_BP384R1;
    ecKeyGroup["bp512r1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1;
    ecKeyGroup["secp192k1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192K1;
    ecKeyGroup["secp224k1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224K1;
    ecKeyGroup["secp256k1"] = VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256K1;

    std::map<std::string, VirgilKeyPairGenerator::ECKeyGroup>::const_iterator group = ecKeyGroup.find(param);
    if (group != ecKeyGroup.end()) {
        return group->second;
    } else {
        return VirgilKeyPairGenerator::ECKeyGroup_DP_NONE;
    }
}

int MAIN(int argc, char **argv) {
    try {
        // Parse arguments.
        TCLAP::CmdLine cmd("Generate private key with given parameters.", ' ', virgil::cli_version());

        TCLAP::ValueArg<std::string> ecArg("e", "ec",
                "Generate elliptic curve key with one of the following curves:\n"
                "\t* bp256r1 - 256-bits Brainpool curve;\n"
                "\t* bp384r1 - 384-bits Brainpool curve;\n"
                "\t* bp512r1 - 512-bits Brainpool curve (default);\n"
                "\t* secp192r1 - 192-bits NIST curve;\n"
                "\t* secp224r1 - 224-bits NIST curve;\n"
                "\t* secp256r1 - 256-bits NIST curve;\n"
                "\t* secp384r1 - 384-bits NIST curve;\n"
                "\t* secp521r1 - 521-bits NIST curve;\n"
                "\t* secp192k1 - 192-bits \"Koblitz\" curve;\n"
                "\t* secp224k1 - 224-bits \"Koblitz\" curve;\n"
                "\t* secp256k1 - 256-bits \"Koblitz\" curve.\n",
                false, "", "curve");

        TCLAP::ValueArg<unsigned int> rsaArg("r", "rsa", "Generate RSA key with a given number of bits.",
                false, 0, "nbits");

        TCLAP::ValueArg<std::string> outArg("o", "out", "Private key. If omitted stdout is used.",
                false, "", "file");

        TCLAP::ValueArg<std::string> pwdArg("p", "pwd", "Private key password.",
                false, "", "arg");

        TCLAP::ValueArg<std::string> formatArg("f", "format", "Output format: der | pem (default).",
                false, "pem", "arg");

        cmd.add(formatArg);
        cmd.add(pwdArg);
        cmd.add(outArg);
        cmd.add(rsaArg);
        cmd.add(ecArg);

        cmd.parse(argc, argv);

        // Prepare output.
        std::ostream *outStream = &std::cout;
        std::ofstream outFile(outArg.getValue().c_str(), std::ios::out | std::ios::binary);
        if (outFile.good()) {
            outStream = &outFile;
        } else if (!outArg.getValue().empty()) {
            throw std::invalid_argument(std::string("can not write file: " + outArg.getValue()));
        }

        // Check parameters
        if (!ecArg.getValue().empty() && rsaArg.getValue() > 0) {
            throw std::invalid_argument("-e, --ec and -r, --rsa parameters are both specified");
        }

        VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
        if (rsaArg.getValue() > 0) {
            // Generate RSA key
            cipher = VirgilAsymmetricCipher::rsa();
            cipher.genKeyPair(VirgilKeyPairGenerator::rsa(rsaArg.getValue()));
        } else {
            // Generate EC key
            VirgilKeyPairGenerator::ECKeyGroup ecKeyGroup = ec_key_group_from_param(ecArg.getValue());
            if (ecKeyGroup == VirgilKeyPairGenerator::ECKeyGroup_DP_NONE) {
                if (ecArg.getValue().empty()) {
                    ecKeyGroup = VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1;
                } else {
                    throw std::invalid_argument(std::string("unknown elliptic curve: ") + ecArg.getValue());
                }
            }
            cipher = VirgilAsymmetricCipher::ec();
            cipher.genKeyPair(VirgilKeyPairGenerator::ec(ecKeyGroup));
        }

        // Export private key
        VirgilByteArray privateKey;
        if (formatArg.getValue() == "pem") {
            privateKey = cipher.exportPrivateKeyToPEM(virgil::str2bytes(pwdArg.getValue()));
        } else if (formatArg.getValue() == "der") {
            privateKey = cipher.exportPrivateKeyToDER(virgil::str2bytes(pwdArg.getValue()));
        } else {
            throw std::invalid_argument(std::string("unknown output format: ") + formatArg.getValue());
        }

        // Output private key
        std::copy(privateKey.begin(), privateKey.end(), std::ostreambuf_iterator<char>(*outStream));
    } catch (TCLAP::ArgException& exception) {
        std::cerr << "Error: " << exception.error() << " for arg " << exception.argId() << std::endl;
        return EXIT_FAILURE;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
