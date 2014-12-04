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

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilUserIdTicket.h>
using virgil::service::data::VirgilUserIdTicket;

#include <virgil/service/data/VirgilUserInfoTicket.h>
using virgil::service::data::VirgilUserInfoTicket;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

VirgilTicket::~VirgilTicket() throw() {}

bool VirgilTicket::isUserIdTicket() const { return false; }

VirgilUserIdTicket& VirgilTicket::asUserIdTicket() {
    if (!isUserIdTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserIdTicket.");
    }
    return dynamic_cast<VirgilUserIdTicket&>(*this);
}

const VirgilUserIdTicket& VirgilTicket::asUserIdTicket() const {
    if (!isUserIdTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserIdTicket.");
    }
    return dynamic_cast<const VirgilUserIdTicket&>(*this);
}

bool VirgilTicket::isUserInfoTicket() const { return false; }

VirgilUserInfoTicket& VirgilTicket::asUserInfoTicket() {
    if (!isUserInfoTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserInfoTicket.");
    }
    return dynamic_cast<VirgilUserInfoTicket&>(*this);
}

const VirgilUserInfoTicket& VirgilTicket::asUserInfoTicket() const {
    if (!isUserInfoTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserInfoTicket.");
    }
    return dynamic_cast<const VirgilUserInfoTicket&>(*this);
}
