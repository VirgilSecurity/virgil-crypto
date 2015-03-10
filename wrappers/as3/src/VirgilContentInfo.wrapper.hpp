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

#ifndef AS3_VIRGIL_CONTENT_INFO_HPP
#define AS3_VIRGIL_CONTENT_INFO_HPP

#include <virgil/crypto/VirgilContentInfo.h>
using virgil::crypto::VirgilContentInfo;

#include "as3_utils.hpp"

enum {
    kContentInfoHeaderMinLength = 16
};

AS3_DECL_FUNC(_wrap_VirgilContentInfo_defineSize, "(asContentInfo:ByteArray):uint") {
    AS3_TO_C_BYTE_ARRAY(asContentInfo, cContentInfo);
    if (cContentInfo.size() < kContentInfoHeaderMinLength) {
        AS3_THROW_EXCEPTION("VirgilContentInfo: Not enough data to determine content info length.");
        return;
    }
    size_t cContentInfoSize = VirgilContentInfo::defineSize(cContentInfo);
    AS3_RETURN_C_UINT(cContentInfoSize);
}

#endif /* AS3_VIRGIL_CONTENT_INFO_HPP */

