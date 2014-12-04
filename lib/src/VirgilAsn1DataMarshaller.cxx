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

#include <virgil/service/data/marshalling/VirgilAsn1DataMarshaller.h>
using virgil::service::data::marshalling::VirgilAsn1DataMarshaller;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <virgil/service/data/VirgilAccount.h>
using virgil::service::data::VirgilAccount;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

#include <virgil/service/data/VirgilUserIdTicket.h>
using virgil::service::data::VirgilUserIdTicket;

#include <virgil/service/data/VirgilUserInfoTicket.h>
using virgil::service::data::VirgilUserInfoTicket;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

#include <virgil/crypto/VirgilAsn1Writer.h>
using virgil::crypto::VirgilAsn1Writer;

#include <virgil/crypto/VirgilAsn1Reader.h>
using virgil::crypto::VirgilAsn1Reader;

#include <cstddef>

static const int kTag_Ticket_UserIdTicket = 0;
static const int kTag_Ticket_UserInfoTicket = 1;

static const int kTag_Ticket_UserIdType_Email = 0;
static const int kTag_Ticket_UserIdType_Phone = 1;
static const int kTag_Ticket_UserIdType_Fax = 2;

static const int kTag_Sign_SignerCertificateId = 0;

/**
 * @code
 *     VirgilAccount ::= SEQUENCE {
 *         id VirgilAccountId
 *     }
 *     VirgilAccountId ::= SEQUENCE {
 *         accountId UTF8String
 *     }
 * @endcode
 */
VirgilByteArray VirgilAsn1DataMarshaller::marshal(const VirgilAccount& account) {
    VirgilAsn1Writer writer;

    /* accountId */
    size_t accountIdLen = 0;
    accountIdLen += writer.writeUTF8String(account.id().accountId());
    accountIdLen += writer.writeSequence(accountIdLen);
    /* account */
    writer.writeSequence(accountIdLen);

    return writer.finish();
}

VirgilAccount * VirgilAsn1DataMarshaller::demarshalAccount(const VirgilByteArray& data) {
    VirgilAsn1Reader reader(data);
    /* account */
    reader.readSequence();
    /* id */
    reader.readSequence();
    /* accountId */
    VirgilByteArray accountId = reader.readUTF8String();

    VirgilAccount *account = new VirgilAccount();
    account->id().setAccountId(accountId);
    return account;
}

/**
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
 */

static size_t marshalCertificate_(const VirgilCertificate& certificate, VirgilAsn1Writer& writer) {
    /* publicKey */
    size_t publicKeyLen = writer.writeOctetString(certificate.publicKey());
    /* id */
    size_t idLen = 0;
    idLen += writer.writeUTF8String(certificate.id().certificateId());
    idLen += writer.writeUTF8String(certificate.id().accountId());
    idLen += writer.writeSequence(idLen);
    /* certificate */
    size_t certificateLen = writer.writeSequence(publicKeyLen + idLen);

    return certificateLen + idLen + publicKeyLen;
}

static VirgilCertificate * demarshalCertificate_(VirgilAsn1Reader& reader) {
    /* certificate */
    reader.readSequence();
    /* id */
    reader.readSequence();
    /* id:accountId */
    VirgilByteArray accountId = reader.readUTF8String();
    /* id:certficateId */
    VirgilByteArray certificateId = reader.readUTF8String();
    /* publicKey */
    VirgilByteArray publicKey = reader.readOctetString();

    VirgilCertificate *certificate = new VirgilCertificate(publicKey);
    certificate->id().setAccountId(accountId);
    certificate->id().setCertificateId(certificateId);

    return certificate;
}

VirgilByteArray VirgilAsn1DataMarshaller::marshal(const VirgilCertificate& certificate) {
    VirgilAsn1Writer writer;
    marshalCertificate_(certificate, writer);
    return writer.finish();
}

VirgilCertificate * VirgilAsn1DataMarshaller::demarshalCertificate(const VirgilByteArray& data) {
    VirgilAsn1Reader reader(data);
    return demarshalCertificate_(reader);
}

/**
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
 */
static size_t marshalTicketDataAndType_(const VirgilUserIdTicket& ticket, VirgilAsn1Writer& writer) {
    size_t dataLen = 0;
    /* data:userIdType */
    dataLen += writer.writeInteger(ticket.userIdType().code());
    /* data:userId */
    dataLen += writer.writeUTF8String(ticket.userId());
    /* data */
    dataLen += writer.writeSequence(dataLen);
    dataLen += writer.writeContextTag(kTag_Ticket_UserIdTicket, dataLen);
    return dataLen;
}

static size_t marshalTicketDataAndType_(const VirgilUserInfoTicket& ticket, VirgilAsn1Writer& writer) {
    size_t dataLen = 0;
    /* data:userAge */
    dataLen += writer.writeInteger(ticket.userAge());
    /* data:userLastName */
    dataLen += writer.writeUTF8String(ticket.userLastName());
    /* data:userFirstName */
    dataLen += writer.writeUTF8String(ticket.userFirstName());
    /* data */
    dataLen += writer.writeSequence(dataLen);
    dataLen += writer.writeContextTag(kTag_Ticket_UserInfoTicket, dataLen);
    return dataLen;
}

VirgilByteArray VirgilAsn1DataMarshaller::marshal(const VirgilTicket& ticket) {
    VirgilAsn1Writer writer;

    /* data and type */
    size_t dataAndTypeLen = 0;
    if (ticket.isUserIdTicket()) {
        dataAndTypeLen += marshalTicketDataAndType_(ticket.asUserIdTicket(), writer);
    } else if (ticket.isUserInfoTicket()) {
        dataAndTypeLen += marshalTicketDataAndType_(ticket.asUserInfoTicket(), writer);
    }
    /* id */
    size_t idLen = 0;
    idLen += writer.writeUTF8String(ticket.id().ticketId());
    idLen += writer.writeUTF8String(ticket.id().certificateId());
    idLen += writer.writeUTF8String(ticket.id().accountId());
    idLen += writer.writeSequence(idLen);
    /* ticket */
    writer.writeSequence(idLen + dataAndTypeLen);

    return writer.finish();
}

static VirgilTicket * demarshalTicketFromUserIdData(VirgilAsn1Reader& reader) {
    /**
     *     VirgilUserIdTicketData ::= SEQUENCE {
     *         userId UTF8String,
     *         userIdType VirgilUserIdType
     *     }
     *     VirgilUserIdType ::= INTEGER {
     *         email(0),
     *         phone(1),
     *         fax(2)
     *     }
     */
    /* data */
    reader.readSequence();
    /* userId */
    VirgilByteArray userId = reader.readUTF8String();
    /* userIdType */
    int userIdType = reader.readInteger();
    VirgilUserIdTicket *ticket = new VirgilUserIdTicket(userId,
            VirgilUserIdType::typeFromCode((VirgilUserIdType::Code)userIdType));
    return ticket;
}

static VirgilTicket * demarshalTicketFromUserInfoData(VirgilAsn1Reader& reader) {
    /**
     *     VirgilUserInfoTicketData ::= SEQUENCE {
     *         userFirstName UTF8String,
     *         userLastName UTF8String,
     *         userAge INTEGER(1..144)
     *     }
     */
     /* data */
    reader.readSequence();
    /* userFirstName */
    VirgilByteArray userFirstName = reader.readUTF8String();
    /* userLastName */
    VirgilByteArray userLastName = reader.readUTF8String();
    /* userAge */
    int userAge = reader.readInteger();

    VirgilTicket *ticket = new VirgilUserInfoTicket(userFirstName, userLastName, userAge);
    return ticket;
}

VirgilTicket * VirgilAsn1DataMarshaller::demarshalTicket(const VirgilByteArray& data) {
    VirgilAsn1Reader reader(data);

    /* ticket */
    reader.readSequence();
    /* id */
    reader.readSequence();
    /* id:accountId */
    VirgilByteArray accountId = reader.readUTF8String();
    /* id:certficateId */
    VirgilByteArray certificateId = reader.readUTF8String();
    /* id:ticketId */
    VirgilByteArray ticketId = reader.readUTF8String();
    /* choice */
    VirgilTicket *ticket = 0;
    if (reader.readContextTag(kTag_Ticket_UserIdTicket)) {
        ticket = demarshalTicketFromUserIdData(reader);
    } else if (reader.readContextTag(kTag_Ticket_UserInfoTicket)) {
        ticket = demarshalTicketFromUserInfoData(reader);
    } else {
        throw VirgilException("ASN.1 demarshalling: Ticket type was not recognized."
                " Possible reason: data was malformed.");
    }

    ticket->id().setAccountId(accountId);
    ticket->id().setCertificateId(certificateId);
    ticket->id().setTicketId(ticketId);
    return ticket;
}

/**
 * @brief Transform VirgilSign object representation to ASN.1 format.
 *
 * @return
 * @code
 *     VirgilSign ::= SEQUENCE {
 *         id [0] VirgilSignId OPTIONAL,
 *         hashName UTF8String,
 *         signedDigest OCTET STRING,
 *         signerCertificateId OCTET STRING
 *     }
 *     VirgilSignId ::= SEQUENCE {
 *         accountId UTF8String,
 *         certificateId UTF8String,
 *         ticketId UTF8String,
 *         signId UTF8String
 *     }
 * @endcode
 */
VirgilByteArray VirgilAsn1DataMarshaller::marshal(const VirgilSign& sign) {
    VirgilAsn1Writer writer;

    /* signerCertificateId */
    size_t certificateIdLen = writer.writeUTF8String(sign.signerCertificateId());
    /* signedDigest */
    size_t signedDigestLen = writer.writeOctetString(sign.signedDigest());
    /* hashName */
    size_t hashNameLen = writer.writeUTF8String(sign.hashName());
    /* id */
    bool idEmpty =
            sign.id().accountId().empty() &&
            sign.id().certificateId().empty() &&
            sign.id().ticketId().empty() &&
            sign.id().signId().empty();
    size_t idLen = 0;
    if (!idEmpty) {
        idLen += writer.writeUTF8String(sign.id().signId());
        idLen += writer.writeUTF8String(sign.id().ticketId());
        idLen += writer.writeUTF8String(sign.id().certificateId());
        idLen += writer.writeUTF8String(sign.id().accountId());
        idLen += writer.writeSequence(idLen);
        idLen += writer.writeContextTag(kTag_Sign_SignerCertificateId, idLen);
    }
    /* sign */
    writer.writeSequence(idLen + certificateIdLen + hashNameLen + signedDigestLen);

    return writer.finish();
}

VirgilSign * VirgilAsn1DataMarshaller::demarshalSign(const VirgilByteArray& data) {
    VirgilAsn1Reader reader(data);
    /* sign */
    reader.readSequence();
    /* id */
    VirgilSignId id;
    if (reader.readContextTag(kTag_Sign_SignerCertificateId)) {
        reader.readSequence();
        /* id:accountId */
        id.setAccountId(reader.readUTF8String());
        /* id:certficateId */
        id.setCertificateId(reader.readUTF8String());
        /* id:ticketId */
        id.setTicketId(reader.readUTF8String());
        /* id:signId */
        id.setSignId(reader.readUTF8String());
    }
    /* hashName */
    VirgilByteArray hashName = reader.readUTF8String();
    /* signedDigest */
    VirgilByteArray signedDigest = reader.readOctetString();
    /* signerCertificateId */
    VirgilByteArray signerCertificateId = reader.readUTF8String();

    VirgilSign *sign = new VirgilSign(hashName, signedDigest, signerCertificateId);
    sign->setId(id);

    return sign;
}
