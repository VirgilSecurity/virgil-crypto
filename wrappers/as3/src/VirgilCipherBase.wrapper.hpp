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

#ifndef AS3_VIRGIL_CIPHER_BASE_HPP
#define AS3_VIRGIL_CIPHER_BASE_HPP

#include <virgil/service/VirgilCipherBase.h>
using virgil::service::VirgilCipherBase;

#include <virgil/crypto/VirgilCustomParams.h>
using virgil::crypto::VirgilCustomParams;

#include "as3_utils.hpp"

AS3_DECL_FUNC(_wrap_VirgilCipherBase_addKeyRecipient,
        "(asSelf:int, asCertificateId:ByteArray, asPublicKey:ByteArray):void") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asCertificateId, cCertificateId);
    AS3_TO_C_BYTE_ARRAY(asPublicKey, cPublicKey);
    cSelf->addKeyRecipient(cCertificateId, cPublicKey);
    AS3_RETURN_VOID();
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilCipherBase_removeKeyRecipient, "(asSelf:int, asCertificateId:ByteArray):void") {
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asCertificateId, cCertificateId);
    cSelf->removeKeyRecipient(cCertificateId);
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCipherBase_addPasswordRecipient, "(asSelf:int, asPassword:ByteArray):void") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asPassword, cPassword);
    cSelf->addPasswordRecipient(cPassword);
    AS3_RETURN_VOID();
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilCipherBase_removePasswordRecipient, "(asSelf:int, asPassword:ByteArray):void") {
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asPassword, cPassword);
    cSelf->removePasswordRecipient(cPassword);
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCipherBase_removeAllRecipients, "(asSelf:int):void") {
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    cSelf->removeAllRecipients();
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCipherBase_getContentInfo, "(asSelf:int):ByteArray") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    VirgilByteArray cContentInfo = cSelf->getContentInfo();
    AS3_RETURN_C_BYTE_ARRAY(cContentInfo);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilCipherBase_setContentInfo, "(asSelf:int, asContentInfo:ByteArray):void") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asContentInfo, cContentInfo);
    cSelf->setContentInfo(cContentInfo);
    AS3_RETURN_VOID();
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilCipherBase_customParameters, "(asSelf:int):int") {
    AS3_TO_C_PTR(VirgilCipherBase, asSelf, cSelf);
    const VirgilCustomParams& cCustomParameters= cSelf->customParameters();
    AS3_RETURN_C_PTR(&cCustomParameters);
}

#endif /* AS3_VIRGIL_CIPHER_BASE_HPP */
