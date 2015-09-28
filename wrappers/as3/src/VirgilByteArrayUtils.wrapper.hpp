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

#ifndef AS3_VIRGIL_BYTE_ARRAY_UTILS_HPP
#define AS3_VIRGIL_BYTE_ARRAY_UTILS_HPP

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;

#include "as3_utils.hpp"

AS3_DECL_FUNC(_wrap_VirgilByteArrayUtils_jsonToBytes, "(asJson:String):ByteArray") {
AS3_THROWABLE_SECTION_START
    AS3_TO_STD_STRING(asJson, cJson);
    VirgilByteArray cBytes = VirgilByteArrayUtils::jsonToBytes(cJson);
    AS3_RETURN_C_BYTE_ARRAY(cBytes);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilByteArrayUtils_stringToBytes, "(asString:String):ByteArray") {
AS3_THROWABLE_SECTION_START
    AS3_TO_STD_STRING(asString, cString);
    VirgilByteArray cBytes = VirgilByteArrayUtils::stringToBytes(cString);
    AS3_RETURN_C_BYTE_ARRAY(cBytes);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilByteArrayUtils_bytesToString, "(asBytes:ByteArray):String") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_BYTE_ARRAY(asBytes, cBytes);
    std::string cString = VirgilByteArrayUtils::bytesToString(cBytes);
    AS3_RETURN_STD_STRING(cString);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilByteArrayUtils_hexToBytes, "(asString:String):ByteArray") {
AS3_THROWABLE_SECTION_START
    AS3_TO_STD_STRING(asString, cString);
    VirgilByteArray cBytes = VirgilByteArrayUtils::hexToBytes(cString);
    AS3_RETURN_C_BYTE_ARRAY(cBytes);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilByteArrayUtils_bytesToHex, "(asBytes:ByteArray, asFormatted:Boolean = false):String") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_BYTE_ARRAY(asBytes, cBytes);
    AS3_TO_C_BOOL(asFormatted, cFormatted);
    std::string cString = VirgilByteArrayUtils::bytesToHex(cBytes, cFormatted);
    AS3_RETURN_STD_STRING(cString);
AS3_THROWABLE_SECTION_END
}

#endif /* AS3_VIRGIL_BYTE_ARRAY_UTILS_HPP */
