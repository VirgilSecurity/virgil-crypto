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

#ifndef AS3_VIRGIL_KEY_PAIR_HPP
#define AS3_VIRGIL_KEY_PAIR_HPP

#include <virgil/crypto/VirgilKeyPair.h>
using virgil::crypto::VirgilKeyPair;

#include "as3_utils.hpp"

AS3_IMPL_DESTRUCTOR(VirgilKeyPair)

AS3_DECL_FUNC(_wrap_new_VirgilKeyPair_init, "(asPublicKey:ByteArray, asPrivateKey:ByteArray):int") {
    AS3_TO_C_BYTE_ARRAY(asPublicKey, cPublicKey);
    AS3_TO_C_BYTE_ARRAY(asPrivateKey, cPrivateKey);
    VirgilKeyPair *cSelf = new VirgilKeyPair(cPublicKey, cPrivateKey);
    AS3_RETURN_C_PTR(cSelf);
}

AS3_DECL_FUNC(_wrap_new_VirgilKeyPair_generate, "(asPassword:ByteArray):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
    VirgilKeyPair *cSelf = new VirgilKeyPair(cPassword);
    AS3_RETURN_C_PTR(cSelf);
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_isKeyPairMatch,
        "(asPublicKey:ByteArray, asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray = null):Boolean") {
    AS3_TO_C_BYTE_ARRAY(asPublicKey, cPublicKey);
    AS3_TO_C_BYTE_ARRAY(asPrivateKey, cPrivateKey);
    AS3_TO_C_BYTE_ARRAY_OPT(asPrivateKeyPassword, cPrivateKeyPassword);
    bool cResult = VirgilKeyPair::isKeyPairMatch(cPublicKey, cPrivateKey, cPrivateKeyPassword);
    AS3_RETURN_C_BOOL(cResult);
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_checkPrivateKeyPassword,
        "(asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray):Boolean") {
    AS3_TO_C_BYTE_ARRAY(asPrivateKey, cPrivateKey);
    AS3_TO_C_BYTE_ARRAY(asPrivateKeyPassword, cPrivateKeyPassword);
    bool cResult = VirgilKeyPair::checkPrivateKeyPassword(cPrivateKey, cPrivateKeyPassword);
    AS3_RETURN_C_BOOL(cResult);
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_isPrivateKeyEncrypted, "(asPrivateKey:ByteArray):Boolean") {
    AS3_TO_C_BYTE_ARRAY(asPrivateKey, cPrivateKey);
    bool cResult = VirgilKeyPair::isPrivateKeyEncrypted(cPrivateKey);
    AS3_RETURN_C_BOOL(cResult);
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_publicKey, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilKeyPair, asSelf, cSelf);
    VirgilByteArray cPublicKey = cSelf->publicKey();
    AS3_RETURN_C_BYTE_ARRAY(cPublicKey);
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_privateKey, "(asSelf:int):ByteArray") {
    AS3_TO_C_PTR(VirgilKeyPair, asSelf, cSelf);
    VirgilByteArray cPrivateKey = cSelf->privateKey();
    AS3_RETURN_C_BYTE_ARRAY(cPrivateKey);
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecNist192, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecNist192(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecNist224, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecNist224(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecNist256, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecNist256(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecNist384, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecNist384(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecNist521, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecNist521(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecBrainpool256, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecBrainpool256(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecBrainpool384, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecBrainpool384(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecBrainpool512, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecBrainpool512(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecKoblitz192, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecKoblitz192(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecKoblitz224, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecKoblitz224(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_ecKoblitz256, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::ecKoblitz256(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_rsa256, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::rsa256(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_rsa512, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::rsa512(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_rsa1024, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::rsa1024(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_rsa2048, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::rsa2048(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilKeyPair_rsa4096, "(asPassword:ByteArray = null):int") {
    AS3_TO_C_BYTE_ARRAY_OPT(asPassword, cPassword);
AS3_THROWABLE_SECTION_START
   VirgilKeyPair *cSelf = new VirgilKeyPair(VirgilKeyPair::rsa4096(cPassword));
    AS3_RETURN_C_PTR(cSelf);
AS3_THROWABLE_SECTION_END
}


#endif /* AS3_VIRGIL_KEY_PAIR_HPP */
