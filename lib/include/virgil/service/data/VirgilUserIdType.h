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

#ifndef VIRGIL_DATA_VIRGIL_USER_ID_TYPE_H
#define VIRGIL_DATA_VIRGIL_USER_ID_TYPE_H

#include <string>

namespace virgil { namespace service { namespace data {

/**
 * @brief This class describes user's specific unique identifier types.
 */
class VirgilUserIdType {
public:
    /**
     * @name Preconfigured types
     */
    ///@{
    static const VirgilUserIdType email;
    static const VirgilUserIdType phone;
    static const VirgilUserIdType fax;
    static const VirgilUserIdType domain;
    static const VirgilUserIdType macAddress;
    static const VirgilUserIdType application;
    ///@}
public:
    /**
     * @brief Type Codes
     */
    typedef enum {
        EmailCode = 0,
        PhoneCode,
        FaxCode,
        DomainCode,
        MacAddressCode,
        ApplicationCode
    } Code;
public:
    /**
     * @brief Creates ticket's identifier with given code.
     */
    static VirgilUserIdType typeFromCode(VirgilUserIdType::Code code);
    /**
     * @brief Creates ticket's identifier with given name.
     */
    static VirgilUserIdType typeFromName(const std::string& name);
    /**
     * @return ticket's identifier type name.
     */
    std::string name() const;
    /**
     * @return ticket's identifier type name.
     */
    VirgilUserIdType::Code code() const;
    /**
     * @return true if ticket's identifier type is email.
     */
    bool isEmail() const;
    /**
     * @return true if ticket's identifier type is phone.
     */
    bool isPhone() const;
    /**
     * @return true if ticket's identifier type is fax.
     */
    bool isFax() const;
    /**
     * @return true if ticket's identifier type is mac address.
     */
    bool isMacAddress() const;
    /**
     * @return true if ticket's identifier type is domain.
     */
    bool isDomain() const;
    /**
     * @return true if ticket's identifier type is application.
     */
    bool isApplication() const;
private:
    /**
     * @brief Configures ticket's identifier with given name and code.
     */
    VirgilUserIdType(const std::string& name, VirgilUserIdType::Code code);
private:
    std::string name_;
    VirgilUserIdType::Code code_;
};

}}}

/**
 * @brief Compares Types to equality.
 */
bool operator==(const virgil::service::data::VirgilUserIdType& lhs, const virgil::service::data::VirgilUserIdType& rhs);

#endif /* VIRGIL_DATA_VIRGIL_ID_TICKET_H */
