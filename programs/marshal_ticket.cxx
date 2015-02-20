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

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilUniqueTicketType.h>
#include <virgil/service/data/VirgilUniqueTicket.h>
using virgil::service::data::VirgilUniqueTicket;

#include <virgil/service/data/VirgilInfoTicketType.h>
#include <virgil/service/data/VirgilInfoTicket.h>
using virgil::service::data::VirgilInfoTicket;

int print_usage(std::ostream& out, const char *programName) {
    out << "Usage: " << programName << " <class_name> <type> <value> <out>" << std::endl;
    out << "    <class_name> - [in]  ticket class: (info_ticket | unique_ticket)" << std::endl;
    out << "    <type>       - [in]  ticket type (email | phone | first_name | ...)" << std::endl;
    out << "    <value>      - [in]  ticket value (any)" << std::endl;
    out << "    <format>     - [in]  marshalling format: json | asn1" << std::endl;
    return -1;
}

int main(int argc, char **argv) {
    // Parse arguments.
    const char *programName = argv[0];
    unsigned currArgPos = 0;

    // Check arguments num.
    if (argc < 5) {
        return print_usage(std::cerr, programName);
    }

    // Parse argument: class_name
    ++currArgPos;
    std::string className = std::string(argv[currArgPos]);

    // Parse argument: type
    ++currArgPos;
    std::string type = std::string(argv[currArgPos]);

    // Parse argument: value
    ++currArgPos;
    VirgilByteArray value = VIRGIL_BYTE_ARRAY_FROM_C_STRING(argv[currArgPos]);

    // Parse argument: format
    ++currArgPos;
    std::string format = std::string(argv[currArgPos]);

    // Create appropriate ticket
    VirgilTicket *ticket = 0;
    if (className == "info_ticket") {
        ticket = new VirgilInfoTicket(virgil_info_ticket_type_from_string(type), value);

    } else if (className == "unique_ticket") {
        ticket = new VirgilUniqueTicket(virgil_unique_ticket_type_from_string(type), value);
    } else {
        std::cerr << "Unknown ticket class: " << className << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Marshal ticket.
    VirgilByteArray data;
    if (format == "asn1") {
        data = ticket->toAsn1();
    } else if (format == "json") {
        data = ticket->toJson();
    } else {
        std::cerr << "Unknown format: " << format << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Write marshalled data to file.
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));

    delete ticket;
    return 0;
}
