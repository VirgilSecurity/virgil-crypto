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

#ifndef VIRGIL_PKI_H
#define VIRGIL_PKI_H

#include <string>
#include <map>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#define VIRGIL_PKI_URL_BASE "https://pki-stg.virgilsecurity.com/"

namespace virgil {

/**
 * @brief Make synchronous request to the Virgil PKI service to retrive certificate for given user.
 * @param userIdType - user's identifier type: email|phone|fax|...
 * @param userId - specific user's identifier, i.e. 'test@test.com'.
 * @return Recipient's certificate.
 * @throw VirgilException - if something wrong.
 */
VirgilCertificate pki_get_certificate(const std::string& userIdType, const std::string& userId);

/**
 * @brief Make synchronous request to the Virgil PKI service to create user with his identifiers.
 * @param publicKey - user's public key.
 * @param ids - user's identifiers.
 * @return user's certificate.
 * @throw VirgilException - if something wrong.
 */
VirgilCertificate pki_create_user(const VirgilByteArray& publicKey, const std::map<std::string, std::string>& ids);

}

#endif /* VIRGIL_PKI_H */
