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

 #include <emscripten/bind.h>
using namespace emscripten;

#include <string>
#include <memory>

#include <virgil/crypto/VirgilVersion.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/VirgilCustomParams.h>

#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/crypto/VirgilCipherBase.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilSigner.h>

namespace virgil { namespace crypto {

static std::string VirgilCryptoException_what(const VirgilCryptoException& exception) {
    return std::string(exception.what());
}

static val VirgilByteArray_data(VirgilByteArray& data) {
    return val(internal::toWireType(typed_memory_view(data.size(), data.data())));
}

static void VirgilByteArray_assign(VirgilByteArray& byteArray, val data) {
    byteArray = vecFromJSArray<VirgilByteArray::value_type>(data);
}

static std::shared_ptr<VirgilCustomParams> VirgilCipherBase_customParams(VirgilCipherBase& cipher) {
    return std::shared_ptr<VirgilCustomParams>(&cipher.customParams());
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

}}

EMSCRIPTEN_BINDINGS(virgil_crypto) {
    class_<virgil::crypto::VirgilVersion>("VirgilVersion")
        .class_function("asNumber", &virgil::crypto::VirgilVersion::asNumber)
        .class_function("asString", &virgil::crypto::VirgilVersion::asString)
        .class_function("majorVersion", &virgil::crypto::VirgilVersion::majorVersion)
        .class_function("minorVersion", &virgil::crypto::VirgilVersion::minorVersion)
        .class_function("patchVersion", &virgil::crypto::VirgilVersion::patchVersion)
    ;

    register_vector<unsigned char>("VirgilByteArray")
        .function("data", virgil::crypto::VirgilByteArray_data)
        .function("assign", virgil::crypto::VirgilByteArray_assign)
    ;

    class_<virgil::crypto::VirgilCryptoException>("VirgilException")
        .constructor<const std::string&>()
        .function("message", &virgil::crypto::VirgilCryptoException_what)
    ;

    class_<virgil::crypto::VirgilKeyPair>("VirgilKeyPair")
        .constructor<>()
        .constructor<const VirgilByteArray&>()
        .constructor<const VirgilByteArray&, const VirgilByteArray&>()
        .function("publicKey", &virgil::crypto::VirgilKeyPair::publicKey)
        .function("privateKey", &virgil::crypto::VirgilKeyPair::privateKey)
    ;

    class_<virgil::crypto::VirgilCipherBase>("VirgilCipherBase")
        .function("addKeyRecipient", &virgil::crypto::VirgilCipherBase::addKeyRecipient)
        .function("removeKeyRecipient", &virgil::crypto::VirgilCipherBase::removeKeyRecipient)
        .function("addPasswordRecipient", &virgil::crypto::VirgilCipherBase::addPasswordRecipient)
        .function("removePasswordRecipient", &virgil::crypto::VirgilCipherBase::removePasswordRecipient)
        .function("removeAllRecipients", &virgil::crypto::VirgilCipherBase::removeAllRecipients)
        .function("getContentInfo", &virgil::crypto::VirgilCipherBase::getContentInfo)
        .function("setContentInfo", &virgil::crypto::VirgilCipherBase::setContentInfo)
        .class_function("defineContentInfoSize", &virgil::crypto::VirgilCipherBase::defineContentInfoSize)
        .function("customParams", &virgil::crypto::VirgilCipherBase_customParams)
    ;

    class_<virgil::crypto::VirgilCipher, base<virgil::crypto::VirgilCipherBase>>("VirgilCipher")
        .constructor<>()
        .function("encrypt", &virgil::crypto::VirgilCipher::encrypt)
        .function("decryptWithKey", &virgil::crypto::VirgilCipher::decryptWithKey)
        .function("decryptWithPassword", &virgil::crypto::VirgilCipher::decryptWithPassword)
    ;

    class_<virgil::crypto::VirgilSigner>("VirgilSigner")
        .constructor<>()
        .constructor<const virgil::crypto::foundation::VirgilHash&>()
        .function("sign", &virgil::crypto::VirgilSigner_sign_1)
        .function("sign", &virgil::crypto::VirgilSigner_sign_2)
        .function("verify", &virgil::crypto::VirgilSigner_verify)
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

EMSCRIPTEN_BINDINGS(virgil_crypto_foundation) {
    class_<virgil::crypto::foundation::VirgilHash>("VirgilHash")
        .constructor<>()
        .class_function("md5", &virgil::crypto::foundation::VirgilHash::md5)
        .class_function("sha256", &virgil::crypto::foundation::VirgilHash::sha256)
        .class_function("sha383", &virgil::crypto::foundation::VirgilHash::sha384)
        .class_function("sha512", &virgil::crypto::foundation::VirgilHash::sha512)
        .function("name", &virgil::crypto::foundation::VirgilHash::name)
        .function("hash", &virgil::crypto::foundation::VirgilHash::hash)
        .function("start", &virgil::crypto::foundation::VirgilHash::start)
        .function("update", &virgil::crypto::foundation::VirgilHash::update)
        .function("finish", &virgil::crypto::foundation::VirgilHash::finish)
        .function("hmac", &virgil::crypto::foundation::VirgilHash::hmac)
        .function("hmacStart", &virgil::crypto::foundation::VirgilHash::hmacStart)
        .function("hmacReset", &virgil::crypto::foundation::VirgilHash::hmacReset)
        .function("hmacUpdate", &virgil::crypto::foundation::VirgilHash::hmacUpdate)
        .function("hmacFinish", &virgil::crypto::foundation::VirgilHash::hmacFinish)
    ;

    class_<virgil::crypto::foundation::VirgilBase64>("VirgilBase64")
        .class_function("encode", &virgil::crypto::foundation::VirgilBase64::encode)
        .class_function("decode", &virgil::crypto::foundation::VirgilBase64::decode)
    ;
}
