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

#ifndef AS3_VIRGIL_INFO_TICKET_HPP
#define AS3_VIRGIL_INFO_TICKET_HPP

#include <virgil/service/data/VirgilInfoTicket.h>
using virgil::service::data::VirgilInfoTicket;

#include "as3_utils.hpp"
#include <iostream>
using namespace std;

AS3_IMPL_CONSTRUCTOR(VirgilInfoTicket)

AS3_DECL_FUNC(_wrap_new_VirgilInfoTicket_init, "(asType:int, asValue:ByteArray):int") {
    AS3_TO_C_ENUM(VirgilInfoTicketType, asType, cType);
    AS3_TO_C_BYTE_ARRAY(asValue, cValue);
    VirgilInfoTicket *ticket = new VirgilInfoTicket(cType, cValue);
    AS3_RETURN_C_PTR(ticket);
}

AS3_IMPL_DESTRUCTOR(VirgilInfoTicket)

AS3_DECL_FUNC(_wrap_VirgilInfoTicket_type, "(asSelf:int):uint") {
    AS3_TO_C_PTR(VirgilInfoTicket, asSelf, cSelf);
    VirgilInfoTicketType cType = cSelf->type();
    AS3_RETURN_C_ENUM(cType);
}

AS3_DECL_FUNC(_wrap_VirgilInfoTicket_value, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilInfoTicket, asSelf, cSelf);
    VirgilByteArray cValue = cSelf->value();
    AS3_RETURN_C_BYTE_ARRAY(cValue);
}

#endif /* AS3_VIRGIL_INFO_TICKET_HPP */
