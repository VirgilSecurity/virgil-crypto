/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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
#include <virgil/crypto/VirgilByteArrayUtils.h>

#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/foundation/VirgilPBKDF.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/VirgilCustomParams.h>

#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/crypto/VirgilCipherBase.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/VirgilTinyCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilRandom;

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
        .class_function("generate", &virgil::crypto::VirgilKeyPair::generate)
        .class_function("generateFrom", &virgil::crypto::VirgilKeyPair::generateFrom)
        .class_function("ecNist192", &virgil::crypto::VirgilKeyPair::ecNist192)
        .class_function("ecNist224", &virgil::crypto::VirgilKeyPair::ecNist224)
        .class_function("ecNist256", &virgil::crypto::VirgilKeyPair::ecNist256)
        .class_function("ecNist384", &virgil::crypto::VirgilKeyPair::ecNist384)
        .class_function("ecNist521", &virgil::crypto::VirgilKeyPair::ecNist521)
        .class_function("ecBrainpool256", &virgil::crypto::VirgilKeyPair::ecBrainpool256)
        .class_function("ecBrainpool384", &virgil::crypto::VirgilKeyPair::ecBrainpool384)
        .class_function("ecBrainpool512", &virgil::crypto::VirgilKeyPair::ecBrainpool512)
        .class_function("ecKoblitz192", &virgil::crypto::VirgilKeyPair::ecKoblitz192)
        .class_function("ecKoblitz224", &virgil::crypto::VirgilKeyPair::ecKoblitz224)
        .class_function("ecKoblitz256", &virgil::crypto::VirgilKeyPair::ecKoblitz256)
        .class_function("rsa256", &virgil::crypto::VirgilKeyPair::rsa256)
        .class_function("rsa512", &virgil::crypto::VirgilKeyPair::rsa512)
        .class_function("rsa1024", &virgil::crypto::VirgilKeyPair::rsa1024)
        .class_function("rsa2048", &virgil::crypto::VirgilKeyPair::rsa2048)
        .class_function("rsa4096", &virgil::crypto::VirgilKeyPair::rsa4096)
        .class_function("isKeyPairMatch", &virgil::crypto::VirgilKeyPair::isKeyPairMatch)
        .class_function("checkPrivateKeyPassword", &virgil::crypto::VirgilKeyPair::checkPrivateKeyPassword)
        .class_function("isPrivateKeyEncrypted", &virgil::crypto::VirgilKeyPair::isPrivateKeyEncrypted)
        .class_function("resetPrivateKeyPassword", &virgil::crypto::VirgilKeyPair::resetPrivateKeyPassword)
        .class_function("extractPublicKey", &virgil::crypto::VirgilKeyPair::extractPublicKey)
    ;

    enum_<virgil::crypto::VirgilKeyPair::Type>("VirgilKeyPairType")
        .value("Default", virgil::crypto::VirgilKeyPair::Type_Default)
        .value("RSA_256", virgil::crypto::VirgilKeyPair::Type_RSA_256)
        .value("RSA_512", virgil::crypto::VirgilKeyPair::Type_RSA_512)
        .value("RSA_1024", virgil::crypto::VirgilKeyPair::Type_RSA_1024)
        .value("RSA_2048", virgil::crypto::VirgilKeyPair::Type_RSA_2048)
        .value("RSA_3072", virgil::crypto::VirgilKeyPair::Type_RSA_3072)
        .value("RSA_4096", virgil::crypto::VirgilKeyPair::Type_RSA_4096)
        .value("RSA_8192", virgil::crypto::VirgilKeyPair::Type_RSA_8192)
        .value("EC_SECP192R1", virgil::crypto::VirgilKeyPair::Type_EC_SECP192R1)
        .value("EC_SECP224R1", virgil::crypto::VirgilKeyPair::Type_EC_SECP224R1)
        .value("EC_SECP256R1", virgil::crypto::VirgilKeyPair::Type_EC_SECP256R1)
        .value("EC_SECP384R1", virgil::crypto::VirgilKeyPair::Type_EC_SECP384R1)
        .value("EC_SECP521R1", virgil::crypto::VirgilKeyPair::Type_EC_SECP521R1)
        .value("EC_BP256R1", virgil::crypto::VirgilKeyPair::Type_EC_BP256R1)
        .value("EC_BP384R1", virgil::crypto::VirgilKeyPair::Type_EC_BP384R1)
        .value("EC_BP512R1", virgil::crypto::VirgilKeyPair::Type_EC_BP512R1)
        .value("EC_CURVE25519", virgil::crypto::VirgilKeyPair::Type_EC_CURVE25519)
        .value("EC_SECP192K1", virgil::crypto::VirgilKeyPair::Type_EC_SECP192K1)
        .value("EC_SECP224K1", virgil::crypto::VirgilKeyPair::Type_EC_SECP224K1)
        .value("EC_SECP256K1", virgil::crypto::VirgilKeyPair::Type_EC_SECP256K1)
    ;

    class_<virgil::crypto::VirgilCipherBase>("VirgilCipherBase")
        .function("addKeyRecipient", &virgil::crypto::VirgilCipherBase::addKeyRecipient)
        .function("removeKeyRecipient", &virgil::crypto::VirgilCipherBase::removeKeyRecipient)
        .function("keyRecipientExists", &virgil::crypto::VirgilCipherBase::keyRecipientExists)
        .function("addPasswordRecipient", &virgil::crypto::VirgilCipherBase::addPasswordRecipient)
        .function("removePasswordRecipient", &virgil::crypto::VirgilCipherBase::removePasswordRecipient)
        .function("removeAllRecipients", &virgil::crypto::VirgilCipherBase::removeAllRecipients)
        .function("getContentInfo", &virgil::crypto::VirgilCipherBase::getContentInfo)
        .function("setContentInfo", &virgil::crypto::VirgilCipherBase::setContentInfo)
        .function("customParams", &virgil::crypto::VirgilCipherBase_customParams)
        .class_function("defineContentInfoSize", &virgil::crypto::VirgilCipherBase::defineContentInfoSize)
        .class_function("computeShared", &virgil::crypto::VirgilCipherBase::computeShared)
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

    class_<virgil::crypto::VirgilByteArrayUtils>("VirgilByteArrayUtils")
        .class_function("jsonToBytes", &virgil::crypto::VirgilByteArrayUtils::jsonToBytes)
        .class_function("bytesToString", &virgil::crypto::VirgilByteArrayUtils::bytesToString)
        .class_function("stringToBytes", &virgil::crypto::VirgilByteArrayUtils::stringToBytes)
        .class_function("hexToBytes", &virgil::crypto::VirgilByteArrayUtils::hexToBytes)
        .class_function("bytesToHex", &virgil::crypto::VirgilByteArrayUtils::bytesToHex)
        .class_function("zeroize", &virgil::crypto::VirgilByteArrayUtils::zeroize)
    ;

    enum_<virgil::crypto::VirgilTinyCipher::PackageSize>("VirgilTinyCipherPackageSize")
        .value("Min", virgil::crypto::VirgilTinyCipher::PackageSize_Min)
        .value("Short_SMS", virgil::crypto::VirgilTinyCipher::PackageSize_Short_SMS)
        .value("Long_SMS", virgil::crypto::VirgilTinyCipher::PackageSize_Long_SMS)
    ;

    class_<virgil::crypto::VirgilTinyCipher>("VirgilTinyCipher")
        .constructor<>()
        .constructor<size_t>()
        .function("reset", &virgil::crypto::VirgilTinyCipher::reset)
        .function("encrypt", &virgil::crypto::VirgilTinyCipher::encrypt)
        .function("encryptAndSign", &virgil::crypto::VirgilTinyCipher::encryptAndSign)
        .function("getPackageCount", &virgil::crypto::VirgilTinyCipher::getPackageCount)
        .function("getPackage", &virgil::crypto::VirgilTinyCipher::getPackage)
        .function("addPackage", &virgil::crypto::VirgilTinyCipher::addPackage)
        .function("isPackagesAccumulated", &virgil::crypto::VirgilTinyCipher::isPackagesAccumulated)
        .function("decrypt", &virgil::crypto::VirgilTinyCipher::decrypt)
        .function("verifyAndDecrypt", &virgil::crypto::VirgilTinyCipher::verifyAndDecrypt)
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

    class_<virgil::crypto::foundation::VirgilPBKDF>("VirgilPBKDF")
        .constructor<>()
        .constructor<const virgil::crypto::VirgilByteArray&>()
        .constructor<const virgil::crypto::VirgilByteArray&, unsigned int>()
        .function("getSalt", &virgil::crypto::foundation::VirgilPBKDF::getSalt)
        .function("getIterationCount", &virgil::crypto::foundation::VirgilPBKDF::getIterationCount)
        .function("setAlgorithm", &virgil::crypto::foundation::VirgilPBKDF::setAlgorithm)
        .function("getAlgorithm", &virgil::crypto::foundation::VirgilPBKDF::getAlgorithm)
        .function("setHash", &virgil::crypto::foundation::VirgilPBKDF::setHash)
        .function("getHash", &virgil::crypto::foundation::VirgilPBKDF::getHash)
        .function("enableRecommendationsCheck", &virgil::crypto::foundation::VirgilPBKDF::enableRecommendationsCheck)
        .function("disableRecommendationsCheck", &virgil::crypto::foundation::VirgilPBKDF::disableRecommendationsCheck)
        .function("derive", &virgil::crypto::foundation::VirgilPBKDF::derive)
    ;

    enum_<virgil::crypto::foundation::VirgilPBKDF::Algorithm>("VirgilPBKDFAlgorithm")
        .value("None", virgil::crypto::foundation::VirgilPBKDF::Algorithm::Algorithm_None)
        .value("PBKDF2", virgil::crypto::foundation::VirgilPBKDF::Algorithm::Algorithm_PBKDF2)
    ;

    enum_<virgil::crypto::foundation::VirgilPBKDF::Hash>("VirgilPBKDFHash")
        .value("SHA1", virgil::crypto::foundation::VirgilPBKDF::Hash::Hash_SHA1)
        .value("SHA224", virgil::crypto::foundation::VirgilPBKDF::Hash::Hash_SHA224)
        .value("SHA256", virgil::crypto::foundation::VirgilPBKDF::Hash::Hash_SHA256)
        .value("SHA384", virgil::crypto::foundation::VirgilPBKDF::Hash::Hash_SHA384)
        .value("SHA512", virgil::crypto::foundation::VirgilPBKDF::Hash::Hash_SHA512)
    ;

    class_<VirgilRandom>("VirgilRandom")
        .constructor<const VirgilByteArray&>()
        .function("randomizeBytes", select_overload<VirgilByteArray(size_t)>(&VirgilRandom::randomize))
        .function("randomizeNumber", select_overload<size_t()>(&VirgilRandom::randomize))
        .function("randomizeNumberInRange", select_overload<size_t(size_t, size_t)>(&VirgilRandom::randomize))
    ;
}
