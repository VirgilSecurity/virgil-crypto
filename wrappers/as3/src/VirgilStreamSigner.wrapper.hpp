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

#ifndef AS3_VIRGIL_STREAM_SIGNER_HPP
#define AS3_VIRGIL_STREAM_SIGNER_HPP

#include <virgil/VirgilStreamSigner.h>
using virgil::VirgilStreamSigner;

#include "as3_utils.hpp"
#include "VirgilDataSourceBridge.hpp"

AS3_DECL_THROWABLE_CONSTRUCTOR(VirgilStreamSigner)
AS3_IMPL_DESTRUCTOR(VirgilStreamSigner)

AS3_DECL_FUNC(_wrap_VirgilStreamSigner_sign,
        "(asSelf:int, asDataSource:*, asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray = null):ByteArray") {
    AS3_TO_C_PTR(VirgilStreamSigner, asSelf, cSelf);
    AS3_TO_C_VAR(asDataSource, cDataSource);
    AS3_TO_C_BYTE_ARRAY(asPrivateKey, cPrivateKey);
    AS3_TO_C_BYTE_ARRAY_OPT(asPrivateKeyPassword, cPrivateKeyPassword);
    VirgilDataSourceBridge cDataSourceBridge(cDataSource);
AS3_THROWABLE_SECTION_START
    VirgilByteArray cSign = cSelf->sign(cDataSourceBridge, cPrivateKey, cPrivateKeyPassword);
    AS3_RETURN_C_BYTE_ARRAY(cSign);
AS3_THROWABLE_SECTION_END

}

AS3_DECL_FUNC(_wrap_VirgilStreamSigner_verify,
        "(asSelf:int, asDataSource:*, asSign:ByteArray, asPublicKey:ByteArray):Boolean") {
    AS3_TO_C_PTR(VirgilStreamSigner, asSelf, cSelf);
    AS3_TO_C_VAR(asDataSource, cDataSource);
    AS3_TO_C_BYTE_ARRAY(asSign, cSign);
    AS3_TO_C_BYTE_ARRAY(asPublicKey, cPublicKey);
    VirgilDataSourceBridge cDataSourceBridge(cDataSource);
AS3_THROWABLE_SECTION_START
    bool cVerified = cSelf->verify(cDataSourceBridge, cSign, cPublicKey);
    AS3_RETURN_C_BOOL(cVerified);
AS3_THROWABLE_SECTION_END

}

#endif /* AS3_VIRGIL_STREAM_SIGNER_HPP */
