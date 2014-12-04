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

#ifndef VIRGIL_DATA_MARCHALLING_VIRGIL_JSON_DATA_MARSHALLER_H
#define VIRGIL_DATA_MARCHALLING_VIRGIL_JSON_DATA_MARSHALLER_H

#include <virgil/service/data/marshalling/VirgilDataMarshaller.h>
using virgil::service::data::marshalling::VirgilDataMarshaller;

namespace virgil { namespace service { namespace data { namespace marshalling {

/**
 * @brief This class provides interface for data-objects' marshalling.
 */
class VirgilJsonDataMarshaller : public VirgilDataMarshaller {
public:
    /**
     * @name Marshaling
     * @brief Transform object representation to Json format.
     */
    ///@{
    /**
     * @brief Transform VirgilAccount object representation to Json format.
     *
     * Json Format:
     * @code
     *    {
     *        "id" : {
     *            "account_id" : "USER-1234"
     *        }
     *    }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilAccount& account);
    /**
     * @brief Transform VirgilCertificate object representation to Json format.
     *
     * Json Format:
     * @code
     *    {
     *      "id" : {
     *         "account_id" : "USER-1234",
     *         "certificate_id" : "CERT-1234"
     *      },
     *      "public_key" : [
     *         "-----BEGIN PUBLIC KEY-----",
     *         "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEA8GVpzCcTiISVsHjuMZg4gvS",
     *         "nIT5ubLZ6TZ8LRzPjYah5h71TrHOgJVXkPtzpFbHdWdvcSsAMbLCnvEnTlXFMDn5",
     *         "3a3YhN+cTdWZCgleKQCc2keY/alCRdgtjL3po90DuT8WcxSreTlVGkE/TZvCZEes",
     *         "o+yIBPaohqMzfjvj4Yw=",
     *         "-----END PUBLIC KEY-----"
     *      ]
     *   }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilCertificate& certificate);
    /**
     * @brief Transform VirgilTicket object representation to Json format.
     *
     * Json Format:
     * @code
     *    {
     *      "id" : {
     *         "account_id" : "USER-1234",
     *         "certificate_id" : "CERT-1234",
     *         "ticket_id" : "TICKET-1234"
     *      },
     *      "type" : "user_id_ticket|user_info_ticket",
     *      "data" : {
     *         "ticket specific key" : "ticket specific value"
     *      }
     *   }
     *   "data of type == userIdTicket" : {
     *      "user_id" : "user@domain.com",
     *      "user_id_type" : "email|phone|fax"
     *   }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilTicket& ticket);
    /**
     * @brief Transform VirgilSign object representation to Json format.
     *
     * Json Format:
     * @code
     *    {
     *       "id" : {
     *          "account_id" : "USER-1234",
     *          "certificate_id" : "CERT-1234",
     *          "ticket_id" : "TICKET-1234",
     *          "sign_id" : "SIGN-1234"
     *       },
     *       "hash_name" : "SHA256",
     *       "signed_digest" : "U0lHTkVELUhBU0g=",
     *       "signer_certificate_id" : "CERT-4321"
     *    }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilSign& sign);
    ///@}
    /**
     * @name Demarshaling
     * @brief Restore object representation from Json format.
     */
    ///@{
    /**
     * @brief Restore VirgilAccount object representation from Json format.
     * @see @link marshal(const VirgilAccount& account) @endlink to inspect Json format details.
     */
    virtual VirgilAccount * demarshalAccount(const VirgilByteArray& data);
    /**
     * @brief Restore VirgilCertificate object representation from Json format.
     * @see @link marshal(const VirgilCertificate& cetfificate) @endlink to inspect Json format details.
     */
    virtual VirgilCertificate * demarshalCertificate(const VirgilByteArray& data);
    /**
     * @brief Restore VirgilTicket object representation from Json format.
     * @see @link marshal(const VirgilTicket& ticket) @endlink to inspect Json format details.
     */
    virtual VirgilTicket * demarshalTicket(const VirgilByteArray& data);
    /**
     * @brief Restore VirgilSign object representation from Json format.
     * @see @link marshal(const VirgilSign& sign) @endlink to inspect Json format details.
     */
    virtual VirgilSign * demarshalSign(const VirgilByteArray& data);
    ///@}
    virtual ~VirgilJsonDataMarshaller() throw() {}
};

}}}}

#endif /* VIRGIL_DATA_MARCHALLING_VIRGIL_JSON_DATA_MARSHALLER_H */
