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

#ifndef AS3_VIRGIL_SIGN_HPP
#define AS3_VIRGIL_SIGN_HPP

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include "as3_utils.hpp"
#include "VirgilIdProvider.wrapper.hpp"

AS3_IMPL_VIRGIL_ID_PROVIDER(VirgilSign)

AS3_IMPL_CONSTRUCTOR(VirgilSign)
AS3_IMPL_DESTRUCTOR(VirgilSign)

AS3_DECL_FUNC(_wrap_new_VirgilSign_init,
        "(asHashName:ByteArray, asSignedDigest:ByteArray, asSignerCertificateId:ByteArray):int") {
    AS3_TO_C_BYTE_ARRAY(asHashName, cHashName);
    AS3_TO_C_BYTE_ARRAY(asSignedDigest, cSignedDigest);
    AS3_TO_C_BYTE_ARRAY(asSignerCertificateId, cSignerCertificateId);

    VirgilSign *cSelf = new VirgilSign(cHashName, cSignedDigest, cSignerCertificateId);

    AS3_RETURN_C_PTR(cSelf);
}

AS3_DECL_FUNC(_wrap_VirgilSign_hashName, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilSign, asSelf, cSelf);
    VirgilByteArray cHashName = cSelf->hashName();
    AS3_RETURN_C_BYTE_ARRAY(cHashName);
}

AS3_DECL_FUNC(_wrap_VirgilSign_signedDigest, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilSign, asSelf, cSelf);
    VirgilByteArray cSignedDigest = cSelf->signedDigest();
    AS3_RETURN_C_BYTE_ARRAY(cSignedDigest);
}

AS3_DECL_FUNC(_wrap_VirgilSign_signerCertificateId, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilSign, asSelf, cSelf);
    VirgilByteArray cSignerCertificateId = cSelf->signerCertificateId();
    AS3_RETURN_C_BYTE_ARRAY(cSignerCertificateId);
}

#endif /* AS3_VIRGIL_SIGN_HPP */
