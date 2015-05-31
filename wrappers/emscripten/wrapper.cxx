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

 #include <emscripten/bind.h>
using namespace emscripten;

#include <string>
#include <memory>

#include <virgil/VirgilVersion.h>
#include <virgil/VirgilException.h>
#include <virgil/VirgilByteArray.h>

#include <virgil/crypto/VirgilHash.h>
#include <virgil/crypto/VirgilBase64.h>
#include <virgil/crypto/VirgilCustomParams.h>

#include <virgil/VirgilKeyPair.h>

#include <virgil/VirgilCipherBase.h>
#include <virgil/VirgilCipher.h>
#include <virgil/VirgilSigner.h>

namespace virgil {

static std::string VirgilException_what(const virgil::VirgilException& exception) {
    return std::string(exception.what());
}

static val VirgilByteArray_data(VirgilByteArray& data) {
    return val(internal::toWireType(typed_memory_view(data.size(), data.data())));
}

static void VirgilByteArray_assign(VirgilByteArray& byteArray, val data) {
    byteArray = vecFromJSArray<VirgilByteArray::value_type>(data);
}

static std::shared_ptr<crypto::VirgilCustomParams> VirgilCipherBase_customParams(VirgilCipherBase& cipher) {
    return std::shared_ptr<crypto::VirgilCustomParams>(&cipher.customParams());
}

static VirgilByteArray VirgilSigner_sign_1(VirgilSigner& signer, const VirgilByteArray& data,
        const VirgilByteArray& privateKey) {
    return signer.sign(data, privateKey);
}

static VirgilByteArray VirgilSigner_sign_2(VirgilSigner& signer, const VirgilByteArray& data,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    return signer.sign(data, privateKey, privateKeyPassword);
}

static bool VirgilSigner_verify(VirgilSigner& signer, const VirgilByteArray& data,
        const VirgilByteArray& sign, const VirgilByteArray& publicKey) {
    return signer.verify(data, sign, publicKey);
}

}

EMSCRIPTEN_BINDINGS(virgil) {
    class_<virgil::VirgilVersion>("VirgilVersion")
        .class_function("asNumber", &virgil::VirgilVersion::asNumber)
        .class_function("asString", &virgil::VirgilVersion::asString)
        .class_function("majorVersion", &virgil::VirgilVersion::majorVersion)
        .class_function("minorVersion", &virgil::VirgilVersion::minorVersion)
        .class_function("patchVersion", &virgil::VirgilVersion::patchVersion)
    ;

    register_vector<unsigned char>("VirgilByteArray")
        .function("data", virgil::VirgilByteArray_data)
        .function("assign", virgil::VirgilByteArray_assign)
    ;

    class_<virgil::VirgilException>("VirgilException")
        .constructor<const std::string&>()
        .function("message", &virgil::VirgilException_what)
    ;

    class_<virgil::VirgilKeyPair>("VirgilKeyPair")
        .constructor<>()
        .constructor<const VirgilByteArray&>()
        .constructor<const VirgilByteArray&, const VirgilByteArray&>()
        .function("publicKey", &virgil::VirgilKeyPair::publicKey)
        .function("privateKey", &virgil::VirgilKeyPair::privateKey)
    ;

    class_<virgil::VirgilCipherBase>("VirgilCipherBase")
        .function("addKeyRecipient", &virgil::VirgilCipherBase::addKeyRecipient)
        .function("removeKeyRecipient", &virgil::VirgilCipherBase::removeKeyRecipient)
        .function("addPasswordRecipient", &virgil::VirgilCipherBase::addPasswordRecipient)
        .function("removePasswordRecipient", &virgil::VirgilCipherBase::removePasswordRecipient)
        .function("removeAllRecipients", &virgil::VirgilCipherBase::removeAllRecipients)
        .function("getContentInfo", &virgil::VirgilCipherBase::getContentInfo)
        .function("setContentInfo", &virgil::VirgilCipherBase::setContentInfo)
        .function("customParams", &virgil::VirgilCipherBase_customParams)
    ;

    class_<virgil::VirgilCipher, base<virgil::VirgilCipherBase>>("VirgilCipher")
        .constructor<>()
        .function("encrypt", &virgil::VirgilCipher::encrypt)
        .function("decryptWithKey", &virgil::VirgilCipher::decryptWithKey)
        .function("decryptWithPassword", &virgil::VirgilCipher::decryptWithPassword)
    ;

    class_<virgil::VirgilSigner>("VirgilSigner")
        .constructor<>()
        .constructor<const virgil::crypto::VirgilHash&>()
        .function("sign", &virgil::VirgilSigner_sign_1)
        .function("sign", &virgil::VirgilSigner_sign_2)
        .function("verify", &virgil::VirgilSigner_verify)
    ;
}

EMSCRIPTEN_BINDINGS(virgil_crypto) {
    class_<virgil::crypto::VirgilHash>("VirgilHash")
        .constructor<>()
        .class_function("md5", &virgil::crypto::VirgilHash::md5)
        .class_function("sha256", &virgil::crypto::VirgilHash::sha256)
        .class_function("sha383", &virgil::crypto::VirgilHash::sha384)
        .class_function("sha512", &virgil::crypto::VirgilHash::sha512)
        .function("name", &virgil::crypto::VirgilHash::name)
        .function("hash", &virgil::crypto::VirgilHash::hash)
        .function("start", &virgil::crypto::VirgilHash::start)
        .function("update", &virgil::crypto::VirgilHash::update)
        .function("finish", &virgil::crypto::VirgilHash::finish)
        .function("hmac", &virgil::crypto::VirgilHash::hmac)
        .function("hmacStart", &virgil::crypto::VirgilHash::hmacStart)
        .function("hmacReset", &virgil::crypto::VirgilHash::hmacReset)
        .function("hmacUpdate", &virgil::crypto::VirgilHash::hmacUpdate)
        .function("hmacFinish", &virgil::crypto::VirgilHash::hmacFinish)
    ;

    class_<virgil::crypto::VirgilBase64>("VirgilBase64")
        .class_function("encode", &virgil::crypto::VirgilBase64::encode)
        .class_function("decode", &virgil::crypto::VirgilBase64::decode)
    ;

    class_<virgil::crypto::VirgilCustomParams>("VirgilCustomParams")
        .constructor<>()
        .function("isEmpty", &virgil::crypto::VirgilCustomParams::isEmpty)
        .function("setInteger", &virgil::crypto::VirgilCustomParams::setInteger)
        .function("getInteger", &virgil::crypto::VirgilCustomParams::getInteger)
        .function("removeInteger", &virgil::crypto::VirgilCustomParams::removeInteger)
        .function("setString", &virgil::crypto::VirgilCustomParams::setString)
        .function("getString", &virgil::crypto::VirgilCustomParams::getString)
        .function("removeString", &virgil::crypto::VirgilCustomParams::removeString)
        .function("setData", &virgil::crypto::VirgilCustomParams::setData)
        .function("getData", &virgil::crypto::VirgilCustomParams::getData)
        .function("removeData", &virgil::crypto::VirgilCustomParams::removeData)
        .function("clear", &virgil::crypto::VirgilCustomParams::clear)
    ;
}
