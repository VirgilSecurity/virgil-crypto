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

#ifndef VIRGIL_DATA_VIRGIL_SIGN_H
#define VIRGIL_DATA_VIRGIL_SIGN_H

#include <virgil/service/data/VirgilIdProvider.h>
using virgil::service::data::VirgilIdProvider;

#include <virgil/service/data/VirgilSignId.h>
using virgil::service::data::VirgilSignId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace virgil { namespace service { namespace data {

/**
 * @brief This class handle information about Virgil Service sign.
 */
class VirgilSign : public VirgilIdProvider<VirgilSignId> {
public:
    /**
     * @brief Configures ticket with type VirgilInfoTicketType_None and with empty value.
     * @note Use this constructor only in conjuction with demarshalling methods.
     * @see fromAsn1()
     * @see fromJson()
     */
    VirgilSign();
    /**
     * @brief Initialize data object.
     * @param hashName - identification name of the hash algorithm (MD5, SHA256, SHA512, etc),
     *                   that was used during sign process.
     * @param signedDigest - data's digital sign.
     * @param signerCertificateId - signer's certificate id, that related to the private key used during sign process.
     */
    VirgilSign(const VirgilByteArray& hashName, const VirgilByteArray& signedDigest,
                const VirgilByteArray& signerCertificateId);
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilSign() throw();
    /**
     * @brief Return identification name of the hash algorithm.
     */
    VirgilByteArray hashName() const;
    /**
     * @brief Return data's digital sign.
     */
    VirgilByteArray signedDigest() const;
    /**
     * @brief Return signer's certificate.
     */
    VirgilByteArray signerCertificateId() const;
    /**
     * @name VirgilAsn1Compatible implementation
     *
     * Marshalling format:
     *     VirgilSign ::= SEQUENCE {
     *         id VirgilSignId,
     *         hashName UTF8String,
     *         signerCertificateId UTF8String
     *         signedDigest OCTET STRING,
     *     }
     *     VirgilSignId ::= SEQUENCE {
     *         accountId UTF8String,
     *         certificateId UTF8String,
     *         ticketId UTF8String,
     *         signId UTF8String
     *     }
     */
    ///@{
    virtual size_t writeAsn1(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes = 0) const;
    virtual void readAsn1(VirgilAsn1Reader& asn1Reader);
    ///@}
    /**
     * @name VirgilJsonCompatible implementation
     *
     * Marshalling format:
     *    {
     *       "id" : {
     *          "account_id" : "UTF8String",
     *          "certificate_id" : "UTF8String",
     *          "ticket_id" : "UTF8String",
     *          "sign_id" : "UTF8String"
     *       },
     *       "hash_name" : "UTF8String",
     *       "signed_digest" : "Base64String",
     *       "signer_certificate_id" : "UTF8String"
     *    }
     */
    ///@{
    virtual Json::Value jsonWrite(Json::Value& childObject) const;
    virtual Json::Value jsonRead(const Json::Value& parentValue);
    ///@}
private:
    VirgilByteArray hashName_;
    VirgilByteArray signedDigest_;
    VirgilByteArray signerCertificateId_;
};

}}}

#endif /* VIRGIL_DATA_VIRGIL_SIGN_H */
