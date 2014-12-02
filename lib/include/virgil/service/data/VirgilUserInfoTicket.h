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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#ifndef VIRGIL_DATA_VIRGIL_USER_INFO_TICKET_H
#define VIRGIL_DATA_VIRGIL_USER_INFO_TICKET_H

#include <cstddef>

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace virgil { namespace service { namespace data {

/**
 * @brief This class describes Virgil Security ticket that contains information about user.
 *
 * The purpose of this ticket is describe user's personal information as first name, last name, age, etc.
 */
class VirgilUserInfoTicket : public VirgilTicket {
public:
    /**
     * @brief Configures ticket with user's first name, last name and age.
     * @note User's first name is a required, when others are optional.
     */
    VirgilUserInfoTicket(const VirgilByteArray& userFirstName, const VirgilByteArray& userLastName, size_t userAge);
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilUserInfoTicket() throw();
    /**
     * @return true.
     */
    virtual bool isUserInfoTicket() const;
    /**
     * @name Accessors
     */
    ///@{
    /**
     * @return user's first name.
     */
    VirgilByteArray userFirstName() const;
    /**
     * @return user's last name.
     */
    VirgilByteArray userLastName() const;
    /**
     * @return user's age.
     */
    size_t userAge() const;
    ///@}
private:
    VirgilByteArray userFirstName_;
    VirgilByteArray userLastName_;
    size_t userAge_;
};

}}}

#endif /* VIRGIL_DATA_VIRGIL_ID_TICKET_H */
