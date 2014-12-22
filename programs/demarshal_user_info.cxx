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

#include <virgil/service/data/marshalling/VirgilDataMarshaller.h>
using virgil::service::data::marshalling::VirgilDataMarshaller;

#include <virgil/service/data/marshalling/VirgilJsonDataMarshaller.h>
using virgil::service::data::marshalling::VirgilJsonDataMarshaller;

#include <virgil/service/data/marshalling/VirgilAsn1DataMarshaller.h>
using virgil::service::data::marshalling::VirgilAsn1DataMarshaller;

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilUserInfoTicket.h>
using virgil::service::data::VirgilUserInfoTicket;

int print_usage(std::ostream& out, const char *programName) {
    out << "Usage: " << programName << " <in> <last_name> <format> <out>" << std::endl;
    out << "    <in>     - [in] file with marshalled user info" << std::endl;
    out << "    <format> - [in] input file marshalling format: json | asn1" << std::endl;
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

    // Parse argument: in
    ++currArgPos;
    std::ifstream inFile(argv[currArgPos], std::ios::in | std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray data;
    std::copy(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>(), std::back_inserter(data));
    inFile.close();

    // Parse argument: format
    ++currArgPos;
    std::string format = std::string(argv[currArgPos]);

    // Create marshaller.
    VirgilDataMarshaller *marshaller = (VirgilDataMarshaller *)0;
    if (format == "json") {
        marshaller = new VirgilJsonDataMarshaller();
    } else if (format == "asn1") {
        marshaller = new VirgilAsn1DataMarshaller();
    } else {
        std::cerr << "Unknown marshalling format was specified: " << format << std::endl;
        return print_usage(std::cerr, programName);
    }

    VirgilTicket *ticket = (VirgilUserInfoTicket *)0;
    try {
        // Demarshal object.
        ticket = marshaller->demarshalTicket(data);

        // Print demarshalled data.
        std::cout << "User's first name is: ";
        std::cout << VIRGIL_BYTE_ARRAY_TO_STD_STRING(ticket->asUserInfoTicket().userFirstName()) << std::endl;
        std::cout << "User's last name is: ";
        std::cout << VIRGIL_BYTE_ARRAY_TO_STD_STRING(ticket->asUserInfoTicket().userLastName()) << std::endl;

        // Dispose resources.
        delete marshaller;
        delete ticket;
    } catch (const std::exception& exception) {
        std::cerr << "Marshalling failed due to exception: " << exception.what() << std::endl;
        if (marshaller) {
            delete marshaller;
        }
        if (ticket) {
            delete ticket;
        }
    }

    return 0;
}
