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

#ifndef AS3_VIRGIL_RANDOM_HPP
#define AS3_VIRGIL_RANDOM_HPP

#include <virgil/crypto/foundation/VirgilRandom.h>
using virgil::crypto::foundation::VirgilRandom;

#include "as3_utils.hpp"

AS3_IMPL_DESTRUCTOR(VirgilRandom)

AS3_DECL_FUNC(_wrap_new_VirgilRandom, "(asPersonalInfo:ByteArray):int") {
    AS3_TO_C_BYTE_ARRAY(asPersonalInfo, cPersonalInfo);
    VirgilRandom *cSelf = new VirgilRandom(cPersonalInfo);
    AS3_RETURN_C_PTR(cSelf);
}

AS3_DECL_FUNC(_wrap_VirgilRandom_randomize, "(asSelf:int, asBytesNum:uint):ByteArray") {
    AS3_TO_C_PTR(VirgilRandom, asSelf, cSelf);
    AS3_TO_C_UINT(asBytesNum, cBytesNum);
    VirgilByteArray cRandomBytes = cSelf->randomize(cBytesNum);
    AS3_RETURN_C_BYTE_ARRAY(cRandomBytes);
}

#endif /* AS3_VIRGIL_RANDOM_HPP */
