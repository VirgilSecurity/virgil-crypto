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

#ifndef VIRGIL_DATA_VIRGIL_TICKET_H
#define VIRGIL_DATA_VIRGIL_TICKET_H

#include <virgil/service/data/VirgilIdProvider.h>
using virgil::service::data::VirgilIdProvider;

#include <virgil/service/data/VirgilTicketId.h>
using virgil::service::data::VirgilTicketId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace virgil { namespace service { namespace data {

class VirgilUniqueTicket;
class VirgilInfoTicket;

/**
 * @brief This base class for all Virgil Security tickets.
 *
 * Ticket - it is user's information (data) that can be signed.
 */
class VirgilTicket : public VirgilIdProvider<VirgilTicketId> {
public:
    /**
     * @name Factory methods
     * @warning Returned object SHOULD be released by the caller.
     */
    ///@{
    /**
     * @brief Create ticket from the ASN.1.
     */
    static VirgilTicket* createFromAsn1(const VirgilByteArray& asn1);
    /**
     * @brief Create ticket from the JSON.
     */
    static VirgilTicket* createFromJson(const VirgilByteArray& json);
    ///@}
public:
    /**
     * @return true if underlying ticket is VirgilUniqueTicket class object.
     * @note Default implementation returns false.
     */
    virtual bool isUniqueTicket() const;
    /**
     * @return current obect with type cast to VirgilUniqueTicket.
     * @exception VirgilException if isUniqueTicket() returns false.
     */
    VirgilUniqueTicket& asUniqueTicket();
    const VirgilUniqueTicket& asUniqueTicket() const;
    /**
     * @return true if underlying ticket is VirgilInfoTicket class object.
     * @note Default implementation returns false.
     */
    virtual bool isInfoTicket() const;
    /**
     * @return current obect with type cast to VirgilInfoTicket.
     * @exception VirgilException if isInfoTicket() returns false.
     */
    VirgilInfoTicket& asInfoTicket();
    const VirgilInfoTicket& asInfoTicket() const;
    /**
     * @name VirgilAsn1Compatible implementation
     *
     * Marshalling format:
     *     VirgilTicket ::= SEQUENCE {
     *         id VirgilTicketId
     *     }
     *     VirgilTicketId ::= SEQUENCE {
     *         accountId UTF8String,
     *         certificateId UTF8String,
     *         ticketId UTF8String
     *     }
     */
    ///@{
    virtual size_t asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes = 0) const;
    virtual void asn1Read(VirgilAsn1Reader& asn1Reader);
    ///@}
    /**
     * @name VirgilJsonCompatible implementation
     *
     * Marshalling format:
     *    {
     *        "id" : {
     *            "account_id" : "UTF8String",
     *            "certificate_id" : "UTF8String",
     *            "ticket_id" : "UTF8String"
     *        }
     *    }
     */
    ///@{
    virtual Json::Value jsonWrite(Json::Value& childObject) const;
    virtual Json::Value jsonRead(const Json::Value& parentValue);
    ///@}
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilTicket() throw();
};

}}}

#endif /* VIRGIL_DATA_VIRGIL_TICKET_H */
