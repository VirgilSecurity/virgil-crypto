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

#ifndef SPLIT_CLI

#include <iostream>
#include <string>
#include <map>

#include "version.h"

typedef int (*main_func)(int argc, char **argv);

int keygen_main(int argc, char **argv);
int key2pub_main(int argc, char **argv);
int pub2cert_main(int argc, char **argv);
int certinfo_main(int argc, char **argv);
int encrypt_main(int argc, char **argv);
int decrypt_main(int argc, char **argv);
int sign_main(int argc, char **argv);
int verify_main(int argc, char **argv);

static void print_usage(std::ostream& out, const char *programName) {
    out << std::endl << "USAGE:" << std::endl;
    out << "    " << programName << " command [command_opts] [command_args]" << std::endl;
    out << std::endl << "DESCRIPTION:" << std::endl;
    out << "    " << "The virgil program is a command line tool for using the various "
            "cryptography functions of the Virgil library." << std::endl;
    out << std::endl << "AVAILABLE COMMANDS:" << std::endl;
    out << "    " << "keygen    " <<
            "Generate private key with a given parameters." << std::endl;
    out << "    " << "key2pub  " <<
            "Extract public key from the private key." << std::endl;
    out << "    " << "pub2cert  " <<
            "Create certificate from the public key and identifiers." << std::endl;
    out << "    " << "certinfo  " <<
            "Output detailed information about given certificate." << std::endl;
    out << "    " << "encrypt   " <<
            "Encrypt data for given recipients which can be defined by certificates and by passwords." << std::endl;
    out << "    " << "decrypt   " <<
            "Decrypt data for given recipient which can be defined by certificate or by password." << std::endl;
    out << "    " << "sign      " <<
            "Sign data with private key." << std::endl;
    out << "    " << "verify    " <<
            "Verify data with certificate." << std::endl;
}

static void print_version(std::ostream& out, const char *programName) {
    out << programName << "  " << "version: "<< cli_version() << std::endl;
}

int main(int argc, char **argv) {
    std::map<std::string, main_func> commandsMap;
    commandsMap["keygen"] = &keygen_main;
    commandsMap["key2pub"] = &key2pub_main;
    commandsMap["pub2cert"] = &pub2cert_main;
    commandsMap["certinfo"] = &certinfo_main;
    commandsMap["encrypt"] = &encrypt_main;
    commandsMap["decrypt"] = &decrypt_main;
    commandsMap["sign"] = &sign_main;
    commandsMap["verify"] = &verify_main;
    // Parse arguments.
    if (argc < 2) {
        std::cerr << "Error: " << " Required argument missing: " << "command" << std::endl;
        print_usage(std::cerr, argv[0]);
        return EXIT_FAILURE;
    }

    std::string firstArg(argv[1]);
    if (firstArg == "-h" || firstArg == "--help") {
        print_usage(std::cout, argv[0]);
        return EXIT_SUCCESS;
    } else if (firstArg == "--version") {
        print_version(std::cout, argv[0]);
        return EXIT_SUCCESS;
    }

    std::map<std::string, main_func>::const_iterator command = commandsMap.find(firstArg);
    if (command != commandsMap.end()) {
        command->second(argc - 1, argv + 1);
    } else {
        std::cerr << "Error: " << "command '" << firstArg << "' not found" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#endif /* SPLIT_CLI */
