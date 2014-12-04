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

#ifndef VIRGIL_DATA_MARCHALLING_VIRGIL_ASN1_DATA_MARSHALLER_H
#define VIRGIL_DATA_MARCHALLING_VIRGIL_ASN1_DATA_MARSHALLER_H

#include <virgil/service/data/marshalling/VirgilDataMarshaller.h>
using virgil::service::data::marshalling::VirgilDataMarshaller;

namespace virgil { namespace service { namespace data { namespace marshalling {

/**
 * @brief This class provides interface for data-objects' marshalling to/from ASN.1 data structure.
 */
class VirgilAsn1DataMarshaller : public VirgilDataMarshaller {
public:
    /**
     * @name Marshaling
     * @brief Transform object representation to ASN.1 format.
     */
    ///@{
    /**
     * @brief Transform VirgilAccount object representation to ASN.1 format.
     *
     * ASN.1 Format:
     * @code
     *     VirgilAccount ::= SEQUENCE {
     *         id VirgilAccountId
     *     }
     *     VirgilAccountId ::= SEQUENCE {
     *         accountId UTF8String
     *     }
     * @endcode
     *
     * ASN.1 Example:
     * @code
     *     account VirgilAccount ::= {
     *         id {
     *             accountId "USER-1234"
     *         }
     *     }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilAccount& account);
    /**
     * @brief Transform VirgilCertificate object representation to ASN.1 format.
     *
     * ASN.1 Format:
     * @code
     *     VirgilCertificate ::= SEQUENCE {
     *         id VirgilCertificateId,
     *         publicKey OCTET STRING
     *     }
     *     VirgilCertificateId ::= SEQUENCE {
     *         accountId UTF8String,
     *         certificateId UTF8String
     *     }
     * @endcode
     *
     * ASN.1 Example:
     * @code
     *     certificate VirgilCertificate ::= {
     *         id {
     *             accountId "USER-1234",
     *             certificateId "CERT-1234"
     *         },
     *         publicKey '2D2D2D2D2D424547494E205055424C4943204B45592D2D2D2D2D0A4D4947624D42514742797147534D3439416745474353736B41774D434341454244514F426767414541384756707A4363546949535673486A754D5A67346776530A6E49543575624C5A36545A384C527A506A596168356837315472484F674A56586B50747A7046624864576476635373414D624C436E76456E546C58464D446E350A33613359684E2B635464575A43676C654B514363326B65592F616C43526467746A4C33706F393044755438576378537265546C56476B452F545A76435A4565730A6F2B79494250616F68714D7A666A766A3459773D0A2D2D2D2D2D454E44205055424C4943204B45592D2D2D2D2D0A'H
     *     }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilCertificate& certificate);
    /**
     * @brief Transform VirgilTicket object representation to ASN.1 format.
     *
     * ASN.1 Format:
     * @code
     *     VirgilTicket ::= SEQUENCE {
     *         id VirgilTicketId,
     *         data CHOICE {
     *             userIdTicketData [0] VirgilUserIdTicketData,
     *             userInfoTicketData [1] VirgilUserInfoTicketData
     *         }
     *     }
     *     VirgilTicketId ::= SEQUENCE {
     *         accountId UTF8String,
     *         certificateId UTF8String,
     *         ticketId UTF8String
     *     }
     *     VirgilUserIdTicketData ::= SEQUENCE {
     *         userId UTF8String,
     *         userIdType VirgilUserIdType
     *     }
     *     VirgilUserIdType ::= INTEGER {
     *         email(0),
     *         phone(1),
     *         fax(2)
     *     }
     *     VirgilUserInfoTicketData ::= SEQUENCE {
     *         userFirstName UTF8String,
     *         userLastName UTF8String,
     *         userAge INTEGER(1..144)
     *     }
     * @endcode
     *
     * ASN.1 Example VirgilUserIdTicket:
     * @code
     *     ticket VirgilTicket ::= {
     *         id {
     *             accountId "USER-1234",
     *             certificateId "CERT-1234",
     *             ticketId "TICKET-1234"
     *         },
     *         data userIdTicketData: {
     *             userId "user@domain.com",
     *             userIdType email
     *         }
     *     }
     * @endcode
     *
     * ASN.1 Example VirgilUserInfoTicket:
     * @code
     *     ticket VirgilTicket ::= {
     *         id {
     *             accountId "USER-1234",
     *             certificateId "CERT-1234",
     *             ticketId "TICKET-1234"
     *         },
     *         data userInfoTicketData: {
     *             userFirstName "Jon",
     *             userLastName "Doe",
     *             userAge 31
     *         }
     *     }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilTicket& ticket);
    /**
     * @brief Transform VirgilSign object representation to ASN.1 format.
     *
     * ASN.1 Format:
     * @code
     *     VirgilSign ::= SEQUENCE {
     *         id [0] VirgilSignId OPTIONAL,
     *         hashName UTF8String,
     *         signedDigest OCTET STRING,
     *         signerCertificateId UTF8String
     *     }
     *     VirgilSignId ::= SEQUENCE {
     *         accountId UTF8String,
     *         certificateId UTF8String,
     *         ticketId UTF8String,
     *         signId UTF8String
     *     }
     * @endcode
     *
     * ASN.1 Example:
     * @code
     *     sign VirgilSign ::= {
     *         id {
     *             accountId "USER-4321",
     *             certificateId "CERT-4321",
     *             ticketId "TICKET-4321",
     *             signId "SIGN-4321"
     *         },
     *         hashName "SHA512",
     *         signedDigest '439416745474353736B41774D434341454244514F426767414541384756707A43635469495356734'H,
     *         signerCertificateId "CERT-1234"
     *     }
     * @endcode
     */
    virtual VirgilByteArray marshal(const VirgilSign& sign);
    ///@}
    /**
     * @name Demarshaling
     * @brief Restore object representation from ASN.1 format.
     */
    ///@{
    /**
     * @brief Restore VirgilAccount object representation from ASN.1 format.
     * @see @link marshal(const VirgilAccount& account) @endlink to inspect ASN.1 format details.
     */
    virtual VirgilAccount * demarshalAccount(const VirgilByteArray& data);
    /**
     * @brief Restore VirgilCertificate object representation from ASN.1 format.
     * @see @link marshal(const VirgilCertificate& cetfificate) @endlink to inspect ASN.1 format details.
     */
    virtual VirgilCertificate * demarshalCertificate(const VirgilByteArray& data);
    /**
     * @brief Restore VirgilTicket object representation from ASN.1 format.
     * @see @link marshal(const VirgilTicket& ticket) @endlink to inspect ASN.1 format details.
     */
    virtual VirgilTicket * demarshalTicket(const VirgilByteArray& data);
    /**
     * @brief Restore VirgilSign object representation from ASN.1 format.
     * @see @link marshal(const VirgilSign& sign) @endlink to inspect ASN.1 format details.
     */
    virtual VirgilSign * demarshalSign(const VirgilByteArray& data);
    ///@}
    /**
     * @brief Empty destructor
     */
    virtual ~VirgilAsn1DataMarshaller() throw() {}
};

}}}}

#endif /* VIRGIL_DATA_MARCHALLING_VIRGIL_ASN1_DATA_MARSHALLER_H */
