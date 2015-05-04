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

#ifndef VIRGIL_PROGRAMS_UTILS_H
#define VIRGIL_PROGRAMS_UTILS_H

#include <cstddef>
#include <string>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <virgil/service/VirgilCipherBase.h>
using virgil::service::VirgilCipherBase;

namespace virgil { namespace cli {

/**
 * @brief Return logical "exclusive or" of 3 arguments.
 */
bool xor3(bool a, bool b, bool c);
/**
 * @brief Returns CLI programs version.
 */
const char * version();
/**
 * @brief Returns filename or directory portion of pathname.
 */
std::string basename(const std::string& path);
/**
 * @brief Returns whether underling data is ASN.1 structure or not.
 */
bool is_asn1(const VirgilByteArray& data);
/**
 * @brief Read certificate from the given file.
 * @param fileName - certfifcate file name.
 * @return Demarshalled certificate.
 * @throw invlaid_argument - if certificate can't be read.
 */
VirgilCertificate read_certificate(const std::string& fileName);
/**
 * @brief Read certificate from the given file.
 * @param file - certfifcate file stream.
 * @param fileName - certfifcate file name.
 * @return Demarshalled certificate.
 * @throw invlaid_argument - if certificate can't be read.
 */
VirgilCertificate read_certificate(std::istream& file, const std::string& fileName = "");
/**
 * @brief Read sign from the given file.
 * @param fileName - certfifcate file name.
 * @return Demarshalled sign.
 * @throw invlaid_argument - if sign can't be read.
 */
VirgilSign read_sign(const std::string& fileName);
/**
 * @brief Read sign from the given file.
 * @param file - certfifcate file stream.
 * @param fileName - certfifcate file name.
 * @return Demarshalled sign.
 * @throw invlaid_argument - if sign can't be read.
 */
VirgilSign read_sign(std::istream& file, const std::string& fileName = "");
/**
 * @brief Add recipients from the configuration files to the cipher.
 * @param cipher - recipients added to.
 * @param configFiles - array of configuration files names.
 * @throw invlaid_argument - if certificate file is empty.
 * @throw VirgilException - if certificate file format is corrupted.
 * return Number of added recipients.
 */
size_t add_recipients_config(VirgilCipherBase& cipher, const std::vector<std::string>& configFiles);
/**
 * @brief Add recipients from the list to the cipher.
 * @param cipher - recipients added to.
 * @param recipients - array of recipients: password and/or certificate.
 * @throw invlaid_argument - if certificate file is empty.
 * @throw VirgilException - if certificate file format is corrupted.
 * return Number of added recipients.
 */
size_t add_recipients(VirgilCipherBase& cipher, const std::vector<std::string>& recipients);
/**
 * @brief Add recipient to the cipher.
 * @param cipher - recipients added to.
 * @param recipient - password and/or certificate.
 * @throw invlaid_argument - if certificate file is empty.
 * @throw VirgilException - if certificate file format is corrupted.
 */
void add_recipient(VirgilCipherBase& cipher, const std::string& recipient);

}}

#endif /* VIRGIL_PROGRAMS_UTILS_H */
