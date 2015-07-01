/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#ifndef AS3_VIRGIL_HASH_HPP
#define AS3_VIRGIL_HASH_HPP

#include <virgil/crypto/foundation/VirgilHash.h>
using virgil::crypto::foundation::VirgilHash;

#include "as3_utils.hpp"

AS3_IMPL_CONSTRUCTOR(VirgilHash)
AS3_IMPL_DESTRUCTOR(VirgilHash)

AS3_DECL_FUNC(_wrap_VirgilHash_md5, "():int") {
AS3_THROWABLE_SECTION_START
    VirgilHash *cSelf = new VirgilHash(VirgilHash::md5());
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_sha256, "():int") {
AS3_THROWABLE_SECTION_START
    VirgilHash *cSelf = new VirgilHash(VirgilHash::sha256());
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_sha384, "():int") {
AS3_THROWABLE_SECTION_START
    VirgilHash *cSelf = new VirgilHash(VirgilHash::sha384());
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_sha512, "():int") {
AS3_THROWABLE_SECTION_START
   VirgilHash *cSelf = new VirgilHash(VirgilHash::sha512());
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_withName, "(asName:ByteArray):int") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_BYTE_ARRAY(asName, cName);
    VirgilHash *cSelf = new VirgilHash(VirgilHash::withName(cName));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_name, "(asSelf:int):String") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
    std::string cName = cSelf->name();
    AS3_RETURN_STD_STRING(cName);
}

AS3_DECL_FUNC(_wrap_VirgilHash_hash, "(asSelf:int, asData:ByteArray):ByteArray") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asData, cData);
AS3_THROWABLE_SECTION_START
    VirgilByteArray cHash = cSelf->hash(cData);
    AS3_RETURN_C_BYTE_ARRAY(cHash);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_start, "(asSelf:int):void") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
AS3_THROWABLE_SECTION_START
    cSelf->start();
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilHash_update, "(asSelf:int, asData:ByteArray):void") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asData, cData);
AS3_THROWABLE_SECTION_START
    cSelf->update(cData);
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilHash_finish, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
AS3_THROWABLE_SECTION_START
    VirgilByteArray cHash = cSelf->finish();
    AS3_RETURN_C_BYTE_ARRAY(cHash);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_hmac, "(asSelf:int, asKey:ByteArray, asData:ByteArray):ByteArray") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    AS3_TO_C_BYTE_ARRAY(asData, cData);
AS3_THROWABLE_SECTION_START
    VirgilByteArray cHmac = cSelf->hmac(cKey, cData);
    AS3_RETURN_C_BYTE_ARRAY(cHmac);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilHash_hmacStart, "(asSelf:int, asKey:ByteArray):void") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
AS3_THROWABLE_SECTION_START
    cSelf->hmacStart(cKey);
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilHash_hmacReset, "(asSelf:int):void") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
AS3_THROWABLE_SECTION_START
    cSelf->hmacReset();
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilHash_hmacUpdate, "(asSelf:int, asData:ByteArray):void") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asData, cData);
AS3_THROWABLE_SECTION_START
    cSelf->hmacUpdate(cData);
AS3_THROWABLE_SECTION_END
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilHash_hmacFinish, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilHash, asSelf, cSelf);
AS3_THROWABLE_SECTION_START
    VirgilByteArray cHmac = cSelf->hmacFinish();
    AS3_RETURN_C_BYTE_ARRAY(cHmac);
AS3_THROWABLE_SECTION_END
}

#endif /* AS3_VIRGIL_HASH_HPP */
