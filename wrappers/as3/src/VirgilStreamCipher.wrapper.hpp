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

#ifndef AS3_VIRGIL_STREAM_CIPHER_HPP
#define AS3_VIRGIL_STREAM_CIPHER_HPP

#include <virgil/VirgilStreamCipher.h>
using virgil::VirgilStreamCipher;

#include "as3_utils.hpp"
#include "VirgilDataSourceBridge.hpp"
#include "VirgilDataSinkBridge.hpp"

AS3_DECL_THROWABLE_CONSTRUCTOR(VirgilStreamCipher)
AS3_IMPL_DESTRUCTOR(VirgilStreamCipher)

AS3_DECL_FUNC(_wrap_VirgilStreamCipher_encrypt,
        "(asSelf:int, asDataSource:*, asDataSink:*, asEmbedContentInfo:Boolean):void") {
    AS3_TO_C_PTR(VirgilStreamCipher, asSelf, cSelf);
    AS3_TO_C_VAR(asDataSource, cDataSource);
    AS3_TO_C_VAR(asDataSink, cDataSink);
    AS3_TO_C_BOOL(asEmbedContentInfo, cEmbedContentInfo);
    VirgilDataSourceBridge cDataSourceBridge(cDataSource);
    VirgilDataSinkBridge cDataSinkBridge(cDataSink);
AS3_THROWABLE_SECTION_START
    cSelf->encrypt(cDataSourceBridge, cDataSinkBridge, cEmbedContentInfo);
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilStreamCipher_decryptWithKey,
        "(asSelf:int, asDataSource:*, asDataSink:*, asCertififcateId:ByteArray, "
        "asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray = null):void") {
    AS3_TO_C_PTR(VirgilStreamCipher, asSelf, cSelf);
    AS3_TO_C_VAR(asDataSource, cDataSource);
    AS3_TO_C_VAR(asDataSink, cDataSink);
    AS3_TO_C_BYTE_ARRAY(asCertififcateId, cCertificateId);
    AS3_TO_C_BYTE_ARRAY(asPrivateKey, cPrivateKey);
    AS3_TO_C_BYTE_ARRAY_OPT(asPrivateKeyPassword, cPrivateKeyPassword);
    VirgilDataSourceBridge cDataSourceBridge(cDataSource);
    VirgilDataSinkBridge cDataSinkBridge(cDataSink);
AS3_THROWABLE_SECTION_START
    cSelf->decryptWithKey(cDataSourceBridge, cDataSinkBridge, cCertificateId, cPrivateKey, cPrivateKeyPassword);
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();

}

AS3_DECL_FUNC(_wrap_VirgilStreamCipher_decryptWithPassword,
        "(asSelf:int, asDataSource:*, asDataSink:*, asPassword:ByteArray):void") {
    AS3_TO_C_PTR(VirgilStreamCipher, asSelf, cSelf);
    AS3_TO_C_VAR(asDataSource, cDataSource);
    AS3_TO_C_VAR(asDataSink, cDataSink);
    AS3_TO_C_BYTE_ARRAY(asPassword, cPassword);
    VirgilDataSourceBridge cDataSourceBridge(cDataSource);
    VirgilDataSinkBridge cDataSinkBridge(cDataSink);
AS3_THROWABLE_SECTION_START
    cSelf->decryptWithPassword(cDataSourceBridge, cDataSinkBridge, cPassword);
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();

}


#endif /* AS3_VIRGIL_STREAM_CIPHER_HPP */
