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

#ifndef VIRGIL_COMMON_PAIR_H
#define VIRGIL_COMMON_PAIR_H

#include <string>
#include <vector>
#include <map>
#include <utility>

namespace virgil {

/**
 * @brief Parse string pair.
 *
 * Pair format: <key>:<value>.
 * @param str - string to be parsed.
 * @return Parsed string pair as std::pair<std::string, std::string>.
 * @throw std::invalid_argument - if given format is invalid.
 *
 * Note, all whitespaces before <key> and after <key> will be trimmed.
 * Note, all whitespaces before <value> and after <value> will be trimmed.
 */
std::pair<std::string, std::string> cli_parse_pair(const std::string& str);

/**
 * @brief Parse array of string pairs.
 *
 * Pair format: <key>:<value>.
 * @param arr - array of strings to be parsed.
 * @return Parsed string pairs.
 * @throw std::invalid_argument - if given format is invalid.
 *
 * Note, all whitespaces before <key> and after <key> will be trimmed.
 * Note, all whitespaces before <value> and after <value> will be trimmed.
 */
std::map<std::string, std::string> cli_parse_pair_array(const std::vector<std::string>& arr);

}

#endif /* VIRGIL_COMMON_PAIR_H */
