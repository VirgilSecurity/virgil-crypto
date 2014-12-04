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

#ifndef VIRGIL_DATA_MARCHALLING_VIRGIL_DATA_MARSHALLER_H
#define VIRGIL_DATA_MARCHALLING_VIRGIL_DATA_MARSHALLER_H

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilAccount.h>
using virgil::service::data::VirgilAccount;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

namespace virgil { namespace service { namespace data { namespace marshalling {

/**
 * @brief This class provides interface for data-objects' marshalling.
 */
class VirgilDataMarshaller {
public:
    /**
     * @name Marshaling
     * @brief Transform object representation to data format suitable for storage or transmission.
     */
    ///@{
    virtual VirgilByteArray marshal(const VirgilAccount& account) = 0;
    virtual VirgilByteArray marshal(const VirgilCertificate& certificate) = 0;
    virtual VirgilByteArray marshal(const VirgilTicket& ticket) = 0;
    virtual VirgilByteArray marshal(const VirgilSign& sign) = 0;
    ///@}
    /**
     * @name Demarshaling
     * @brief Restore object representation from data format suitable for storage or transmission.
     */
    ///@{
    virtual VirgilAccount * demarshalAccount(const VirgilByteArray& data) = 0;
    virtual VirgilCertificate * demarshalCertificate(const VirgilByteArray& data) = 0;
    virtual VirgilTicket * demarshalTicket(const VirgilByteArray& data) = 0;
    virtual VirgilSign * demarshalSign(const VirgilByteArray& data) = 0;
    ///@}
    virtual ~VirgilDataMarshaller() throw() {}
};

}}}}

#endif /* VIRGIL_DATA_MARCHALLING_VIRGIL_DATA_MARSHALLER_H */
