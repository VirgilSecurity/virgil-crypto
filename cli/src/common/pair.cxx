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

#include <cli/pair.h>

#include <cstddef>
#include <stdexcept>

static std::string trim(const std::string& s, const std::string& delimiters = " \f\n\r\t\v" ) {
    std::string result = s;
    result.erase(result.find_last_not_of(delimiters) + 1);
    result.erase(0, result.find_first_not_of(delimiters));
    return result;
}

std::pair<std::string, std::string> virgil::cli_parse_pair(const std::string& str) {
    size_t delimPos = str.find_first_of(':');
    if (delimPos == std::string::npos || delimPos == (str.size() - 1)) {
        throw std::invalid_argument(std::string("invalid pair format: ") + str +
                ". Expected format: '<key>:<value>'.");
    }
    return std::make_pair(trim(str.substr(0, delimPos)), trim(str.substr(delimPos + 1)));
}

std::map<std::string, std::string> virgil::cli_parse_pair_array(const std::vector<std::string>& arr) {
    std::map<std::string, std::string> result;
    for (std::vector<std::string>::const_iterator pair = arr.begin(); pair != arr.end(); ++pair) {
        result.insert(virgil::cli_parse_pair(*pair));
    }
    return result;
}
