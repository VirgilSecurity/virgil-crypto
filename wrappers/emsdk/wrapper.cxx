/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <string>
#include <memory>

#include "VirgilConfig.h"

#include <virgil/crypto/VirgilVersion.h>
#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>

#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/foundation/VirgilPBKDF.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/VirgilPBE.h>
#include <virgil/crypto/foundation/VirgilHKDF.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>
#include <virgil/crypto/VirgilCustomParams.h>

#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/crypto/VirgilCipherBase.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilSignerBase.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/VirgilTinyCipher.h>
#include <virgil/crypto/VirgilDataSink.h>
#include <virgil/crypto/VirgilDataSource.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/VirgilChunkCipher.h>

#include <virgil/crypto/pfs/VirgilPFSSession.h>
#include <virgil/crypto/pfs/VirgilPFSEncryptedMessage.h>
#include <virgil/crypto/pfs/VirgilPFSPublicKey.h>
#include <virgil/crypto/pfs/VirgilPFSPrivateKey.h>
#include <virgil/crypto/pfs/VirgilPFSInitiatorPublicInfo.h>
#include <virgil/crypto/pfs/VirgilPFSInitiatorPrivateInfo.h>
#include <virgil/crypto/pfs/VirgilPFSResponderPublicInfo.h>
#include <virgil/crypto/pfs/VirgilPFSResponderPrivateInfo.h>
#include <virgil/crypto/pfs/VirgilPFS.h>

#include "@VIRGIL_EMBIND_FILE@"

using namespace emscripten;
using namespace virgil::crypto;
using namespace virgil::crypto::foundation;
using namespace virgil::crypto::pfs;

namespace virgil { namespace crypto {

static val VirgilByteArray_data(VirgilByteArray& data) {
    return val(internal::toWireType(typed_memory_view(data.size(), data.data())));
}

static void VirgilByteArray_assign(VirgilByteArray& byteArray, val data) {
    byteArray = vecFromJSArray<VirgilByteArray::value_type>(data);
}

static VirgilCustomParams* VirgilCipherBase_customParams(VirgilCipherBase& cipher) {
    return &cipher.customParams();
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

class VirgilDataSinkWrapper : public wrapper<VirgilDataSink> {
public:
    EMSCRIPTEN_WRAPPER(VirgilDataSinkWrapper);
    bool isGood() {
        return call<bool>("isGood");
    }
    void write(const VirgilByteArray& data) {
        return call<void>("write", data);
    }
};

class VirgilDataSourceWrapper : public wrapper<VirgilDataSource> {
public:
    EMSCRIPTEN_WRAPPER(VirgilDataSourceWrapper);
    bool hasData() {
        return call<bool>("hasData");
    }
    VirgilByteArray read() {
        return call<VirgilByteArray>("read");
    }
};

}}

EMSCRIPTEN_BINDINGS(virgil_crypto) {
    class_<VirgilVersion>("VirgilVersion")
        .class_function("asNumber", &VirgilVersion::asNumber)
        .class_function("asString", &VirgilVersion::asString)
        .class_function("fullName", &VirgilVersion::fullName)
        .class_function("majorVersion", &VirgilVersion::majorVersion)
        .class_function("minorVersion", &VirgilVersion::minorVersion)
        .class_function("patchVersion", &VirgilVersion::patchVersion)
    ;

    class_<VirgilConfig>("Config")
        .class_function("hasFeatureStreamImpl", &VirgilConfig::hasFeatureStreamImpl)
        .class_function("hasFeaturePythiaImpl", &VirgilConfig::hasFeaturePythiaImpl)
        .class_function("hasFeaturePythiaMultiThread", &VirgilConfig::hasFeaturePythiaMultiThread)
    ;

    register_vector<unsigned char>("VirgilByteArray")
        .function("data", VirgilByteArray_data)
        .function("assign", VirgilByteArray_assign)
    ;

    class_<VirgilKeyPair>("VirgilKeyPair")
        .constructor<const VirgilByteArray&, const VirgilByteArray&>()
        .function("publicKey", &VirgilKeyPair::publicKey)
        .function("privateKey", &VirgilKeyPair::privateKey)
        .class_function("generate", &VirgilKeyPair::generate)
        .class_function("generateRecommended", &VirgilKeyPair::generateRecommended)
        .class_function("generateFrom", &VirgilKeyPair::generateFrom)
        .class_function("isKeyPairMatch", &VirgilKeyPair::isKeyPairMatch)
        .class_function("checkPrivateKeyPassword", &VirgilKeyPair::checkPrivateKeyPassword)
        .class_function("isPrivateKeyEncrypted", &VirgilKeyPair::isPrivateKeyEncrypted)
        .class_function("resetPrivateKeyPassword", &VirgilKeyPair::resetPrivateKeyPassword)
        .class_function("extractPublicKey", &VirgilKeyPair::extractPublicKey)
        .class_function("encryptPrivateKey", &VirgilKeyPair::encryptPrivateKey)
        .class_function("decryptPrivateKey", &VirgilKeyPair::decryptPrivateKey)
        .class_function("publicKeyToPEM", &VirgilKeyPair::publicKeyToPEM)
        .class_function("publicKeyToDER", &VirgilKeyPair::publicKeyToDER)
        .class_function("privateKeyToPEM", &VirgilKeyPair::privateKeyToPEM)
        .class_function("privateKeyToDER", &VirgilKeyPair::privateKeyToDER)
    ;

    enum_<VirgilKeyPair::Type>("VirgilKeyPairType")
        .value("RSA_256", VirgilKeyPair::Type::RSA_256)
        .value("RSA_512", VirgilKeyPair::Type::RSA_512)
        .value("RSA_1024", VirgilKeyPair::Type::RSA_1024)
        .value("RSA_2048", VirgilKeyPair::Type::RSA_2048)
        .value("RSA_3072", VirgilKeyPair::Type::RSA_3072)
        .value("RSA_4096", VirgilKeyPair::Type::RSA_4096)
        .value("RSA_8192", VirgilKeyPair::Type::RSA_8192)
        .value("EC_SECP192R1", VirgilKeyPair::Type::EC_SECP192R1)
        .value("EC_SECP224R1", VirgilKeyPair::Type::EC_SECP224R1)
        .value("EC_SECP256R1", VirgilKeyPair::Type::EC_SECP256R1)
        .value("EC_SECP384R1", VirgilKeyPair::Type::EC_SECP384R1)
        .value("EC_SECP521R1", VirgilKeyPair::Type::EC_SECP521R1)
        .value("EC_BP256R1", VirgilKeyPair::Type::EC_BP256R1)
        .value("EC_BP384R1", VirgilKeyPair::Type::EC_BP384R1)
        .value("EC_BP512R1", VirgilKeyPair::Type::EC_BP512R1)
        .value("EC_SECP192K1", VirgilKeyPair::Type::EC_SECP192K1)
        .value("EC_SECP224K1", VirgilKeyPair::Type::EC_SECP224K1)
        .value("EC_SECP256K1", VirgilKeyPair::Type::EC_SECP256K1)
        .value("EC_CURVE25519", VirgilKeyPair::Type::EC_CURVE25519)
        .value("FAST_EC_X25519", VirgilKeyPair::Type::FAST_EC_X25519)
        .value("FAST_EC_ED25519", VirgilKeyPair::Type::FAST_EC_ED25519)
    ;

    class_<VirgilCipherBase>("VirgilCipherBase")
        .function("addKeyRecipient", &VirgilCipherBase::addKeyRecipient)
        .function("removeKeyRecipient", &VirgilCipherBase::removeKeyRecipient)
        .function("keyRecipientExists", &VirgilCipherBase::keyRecipientExists)
        .function("addPasswordRecipient", &VirgilCipherBase::addPasswordRecipient)
        .function("removePasswordRecipient", &VirgilCipherBase::removePasswordRecipient)
        .function("removeAllRecipients", &VirgilCipherBase::removeAllRecipients)
        .function("getContentInfo", &VirgilCipherBase::getContentInfo)
        .function("setContentInfo", &VirgilCipherBase::setContentInfo)
        .function("customParams", &VirgilCipherBase_customParams, allow_raw_pointers())
        .class_function("defineContentInfoSize", &VirgilCipherBase::defineContentInfoSize)
        .class_function("computeShared", &VirgilCipherBase::computeShared)
    ;

    class_<VirgilCipher, base<VirgilCipherBase>>("VirgilCipher")
        .constructor<>()
        .function("encrypt", &VirgilCipher::encrypt)
        .function("decryptWithKey", &VirgilCipher::decryptWithKey)
        .function("decryptWithPassword", &VirgilCipher::decryptWithPassword)
    ;

    class_<VirgilSignerBase>("VirgilSignerBase")
        .constructor<>()
        .constructor<VirgilHash::Algorithm>()
        .function("getHashAlgorithm", &VirgilSignerBase::getHashAlgorithm)
        .function("signHash", &VirgilSignerBase::signHash)
        .function("verifyHash", &VirgilSignerBase::verifyHash)
    ;

    class_<VirgilSigner, base<VirgilSignerBase>>("VirgilSigner")
        .constructor<>()
        .constructor<VirgilHash::Algorithm>()
        .function("sign", &VirgilSigner_sign_1)
        .function("sign", &VirgilSigner_sign_2)
        .function("verify", &VirgilSigner_verify)
    ;

    class_<VirgilCustomParams>("VirgilCustomParams")
        .constructor<>()
        .function("isEmpty", &VirgilCustomParams::isEmpty)
        .function("setInteger", &VirgilCustomParams::setInteger)
        .function("getInteger", &VirgilCustomParams::getInteger)
        .function("removeInteger", &VirgilCustomParams::removeInteger)
        .function("setString", &VirgilCustomParams::setString)
        .function("getString", &VirgilCustomParams::getString)
        .function("removeString", &VirgilCustomParams::removeString)
        .function("setData", &VirgilCustomParams::setData)
        .function("getData", &VirgilCustomParams::getData)
        .function("removeData", &VirgilCustomParams::removeData)
        .function("clear", &VirgilCustomParams::clear)
    ;

    class_<VirgilByteArrayUtils>("VirgilByteArrayUtils")
        .class_function("jsonToBytes", &VirgilByteArrayUtils::jsonToBytes)
        .class_function("bytesToString", &VirgilByteArrayUtils::bytesToString)
        .class_function("stringToBytes", &VirgilByteArrayUtils::stringToBytes)
        .class_function("hexToBytes", &VirgilByteArrayUtils::hexToBytes)
        .class_function("bytesToHex", &VirgilByteArrayUtils::bytesToHex)
        .class_function("zeroize", &VirgilByteArrayUtils::zeroize)
    ;

    enum_<VirgilTinyCipher::PackageSize>("VirgilTinyCipherPackageSize")
        .value("Min", VirgilTinyCipher::PackageSize_Min)
        .value("Short_SMS", VirgilTinyCipher::PackageSize_Short_SMS)
        .value("Long_SMS", VirgilTinyCipher::PackageSize_Long_SMS)
    ;

    class_<VirgilTinyCipher>("VirgilTinyCipher")
        .constructor<>()
        .constructor<size_t>()
        .function("reset", &VirgilTinyCipher::reset)
        .function("encrypt", &VirgilTinyCipher::encrypt)
        .function("encryptAndSign", &VirgilTinyCipher::encryptAndSign)
        .function("getPackageCount", &VirgilTinyCipher::getPackageCount)
        .function("getPackage", &VirgilTinyCipher::getPackage)
        .function("addPackage", &VirgilTinyCipher::addPackage)
        .function("isPackagesAccumulated", &VirgilTinyCipher::isPackagesAccumulated)
        .function("decrypt", &VirgilTinyCipher::decrypt)
        .function("verifyAndDecrypt", &VirgilTinyCipher::verifyAndDecrypt)
    ;

    class_<VirgilDataSink>("VirgilDataSink")
        .function("isGood", &VirgilDataSink::isGood, pure_virtual())
        .function("write", &VirgilDataSink::write, pure_virtual())
        .allow_subclass<VirgilDataSinkWrapper>("VirgilDataSinkWrapper")
    ;

    class_<VirgilDataSource>("VirgilDataSource")
        .function("hasData", &VirgilDataSource::hasData, pure_virtual())
        .function("read", &VirgilDataSource::read, pure_virtual())
        .allow_subclass<VirgilDataSourceWrapper>("VirgilDataSourceWrapper")
    ;

    class_<VirgilStreamCipher, base<VirgilCipherBase>>("VirgilStreamCipher")
        .constructor<>()
        .function("encrypt", &VirgilStreamCipher::encrypt)
        .function("decryptWithKey", &VirgilStreamCipher::decryptWithKey)
        .function("decryptWithPassword", &VirgilStreamCipher::decryptWithPassword)
    ;

    class_<VirgilStreamSigner>("VirgilStreamSigner")
        .constructor<>()
        .function("sign", &VirgilStreamSigner::sign)
        .function("verify", &VirgilStreamSigner::verify)
    ;

    class_<VirgilChunkCipher, base<VirgilCipherBase>>("VirgilChunkCipher")
        .constructor<>()
        .function("encrypt", &VirgilChunkCipher::encrypt)
        .function("decryptWithKey", &VirgilChunkCipher::decryptWithKey)
        .function("decryptWithPassword", &VirgilChunkCipher::decryptWithPassword)
    ;
}

EMSCRIPTEN_BINDINGS(virgil_crypto_foundation) {
    class_<VirgilHash>("VirgilHash")
        .constructor<VirgilHash::Algorithm>()
        .function("name", &VirgilHash::name)
        .function("hash", &VirgilHash::hash)
        .function("start", &VirgilHash::start)
        .function("update", &VirgilHash::update)
        .function("finish", &VirgilHash::finish)
        .function("hmac", &VirgilHash::hmac)
        .function("hmacStart", &VirgilHash::hmacStart)
        .function("hmacReset", &VirgilHash::hmacReset)
        .function("hmacUpdate", &VirgilHash::hmacUpdate)
        .function("hmacFinish", &VirgilHash::hmacFinish)
        .function("getSize", &VirgilHash::size)
        .function("getTypeId", &VirgilHash::type)
    ;

    enum_<VirgilHash::Algorithm>("VirgilHashAlgorithm")
        .value("MD5", VirgilHash::Algorithm::MD5)
        .value("SHA1", VirgilHash::Algorithm::SHA1)
        .value("SHA224", VirgilHash::Algorithm::SHA224)
        .value("SHA256", VirgilHash::Algorithm::SHA256)
        .value("SHA384", VirgilHash::Algorithm::SHA384)
        .value("SHA512", VirgilHash::Algorithm::SHA512)
    ;

    class_<VirgilBase64>("VirgilBase64")
        .class_function("encode", &VirgilBase64::encode)
        .class_function("decode", &VirgilBase64::decode)
    ;

    class_<VirgilPBKDF>("VirgilPBKDF")
        .constructor<const VirgilByteArray&>()
        .constructor<const VirgilByteArray&, unsigned int>()
        .function("getSalt", &VirgilPBKDF::getSalt)
        .function("getIterationCount", &VirgilPBKDF::getIterationCount)
        .function("setAlgorithm", &VirgilPBKDF::setAlgorithm)
        .function("getAlgorithm", &VirgilPBKDF::getAlgorithm)
        .function("setHashAlgorithm", &VirgilPBKDF::setHashAlgorithm)
        .function("getHashAlgorithm", &VirgilPBKDF::getHashAlgorithm)
        .function("enableRecommendationsCheck", &VirgilPBKDF::enableRecommendationsCheck)
        .function("disableRecommendationsCheck", &VirgilPBKDF::disableRecommendationsCheck)
        .function("derive", &VirgilPBKDF::derive)
    ;

    enum_<VirgilPBKDF::Algorithm>("VirgilPBKDFAlgorithm")
        .value("PBKDF2", VirgilPBKDF::Algorithm::PBKDF2)
    ;

    class_<VirgilRandom>("VirgilRandom")
        .constructor<const VirgilByteArray&>()
        .function("randomizeBytes", select_overload<VirgilByteArray(size_t)>(&VirgilRandom::randomize))
        .function("randomizeNumber", select_overload<size_t()>(&VirgilRandom::randomize))
        .function("randomizeNumberInRange", select_overload<size_t(size_t, size_t)>(&VirgilRandom::randomize))
    ;

    class_<VirgilPBE>("VirgilPBE")
        .constructor<VirgilPBE::Algorithm, VirgilByteArray>()
        .constructor<VirgilPBE::Algorithm, VirgilByteArray, size_t>()
        .function("encrypt", &VirgilPBE::encrypt)
        .function("decrypt", &VirgilPBE::decrypt)
    ;

    enum_<VirgilPBE::Algorithm>("VirgilPBEAlgorithm")
        .value("PKCS5", VirgilPBE::Algorithm::PKCS5)
        .value("PKCS12", VirgilPBE::Algorithm::PKCS12)
    ;

    class_<VirgilHKDF>("VirgilHKDF")
        .constructor<VirgilHash::Algorithm>()
        .function("derive", &VirgilHKDF::derive)
    ;

    class_<VirgilSymmetricCipher>("VirgilSymmetricCipher")
        .constructor<VirgilSymmetricCipher::Algorithm>()
        .function("getName", &VirgilSymmetricCipher::name)
        .function("getBlockSize", &VirgilSymmetricCipher::blockSize)
        .function("getIvSize", &VirgilSymmetricCipher::ivSize)
        .function("getKeySize", &VirgilSymmetricCipher::keyLength) /* rename keyLength -> getKeySize */
        .function("getKeySizeBits", &VirgilSymmetricCipher::keySize) /* rename keySize -> getKeySizeBits */
        .function("getAuthTagSize", &VirgilSymmetricCipher::authTagLength)
        .function("getIV", &VirgilSymmetricCipher::iv)
        .function("setIV", &VirgilSymmetricCipher::setIV)
        .function("setAuthData", &VirgilSymmetricCipher::setAuthData)
        .function("isEncryptionMode", &VirgilSymmetricCipher::isEncryptionMode)
        .function("isDecryptionMode", &VirgilSymmetricCipher::isDecryptionMode)
        .function("isAuthMode", &VirgilSymmetricCipher::isAuthMode)
        .function("isSupportPadding", &VirgilSymmetricCipher::isSupportPadding)
        .function("setEncryptionKey", &VirgilSymmetricCipher::setEncryptionKey)
        .function("setDecryptionKey", &VirgilSymmetricCipher::setDecryptionKey)
        .function("setPadding", &VirgilSymmetricCipher::setPadding)
        .function("reset", &VirgilSymmetricCipher::reset)
        .function("clear", &VirgilSymmetricCipher::clear)
        .function("update", &VirgilSymmetricCipher::update)
        .function("finish", &VirgilSymmetricCipher::finish)
    ;


    enum_<VirgilSymmetricCipher::Padding>("VirgilSymmetricCipherPadding")
        .value("PKCS7", VirgilSymmetricCipher::Padding::PKCS7)
        .value("OneAndZeros", VirgilSymmetricCipher::Padding::OneAndZeros)
        .value("ZerosAndLen", VirgilSymmetricCipher::Padding::ZerosAndLen)
        .value("Zeros", VirgilSymmetricCipher::Padding::Zeros)
        .value("None", VirgilSymmetricCipher::Padding::None)
    ;

    enum_<VirgilSymmetricCipher::Algorithm>("VirgilSymmetricCipherAlgorithm")
        .value("AES_128_CBC", VirgilSymmetricCipher::Algorithm::AES_128_CBC)
        .value("AES_128_GCM", VirgilSymmetricCipher::Algorithm::AES_128_GCM)
        .value("AES_256_CBC", VirgilSymmetricCipher::Algorithm::AES_256_CBC)
        .value("AES_256_GCM", VirgilSymmetricCipher::Algorithm::AES_256_GCM)
    ;

    class_<VirgilAsymmetricCipher>("VirgilAsymmetricCipher")
        .constructor<>()
        .function("getKeySizeBits", &VirgilAsymmetricCipher::keySize)
        .function("getKeySize", &VirgilAsymmetricCipher::keyLength)
        .class_function("isKeyPairMatch", &VirgilAsymmetricCipher::isKeyPairMatch)
        .class_function("isPublicKeyValid", &VirgilAsymmetricCipher::isPublicKeyValid)
        .class_function("checkPublicKey", &VirgilAsymmetricCipher::checkPublicKey)
        .class_function("checkPrivateKeyPassword", &VirgilAsymmetricCipher::checkPrivateKeyPassword)
        .class_function("isPrivateKeyEncrypted", &VirgilAsymmetricCipher::isPrivateKeyEncrypted)
        .function("setPrivateKey", &VirgilAsymmetricCipher::setPrivateKey)
        .function("setPublicKey", &VirgilAsymmetricCipher::setPublicKey)
        .function("genKeyPair", &VirgilAsymmetricCipher::genKeyPair)
        .function("genKeyPairFrom", &VirgilAsymmetricCipher::genKeyPairFrom)
        .class_function("computeShared", &VirgilAsymmetricCipher::computeShared)
        .function("exportPrivateKeyToDER", &VirgilAsymmetricCipher::exportPrivateKeyToDER)
        .function("exportPublicKeyToDER", &VirgilAsymmetricCipher::exportPublicKeyToDER)
        .function("exportPrivateKeyToPEM", &VirgilAsymmetricCipher::exportPrivateKeyToPEM)
        .function("exportPublicKeyToPEM", &VirgilAsymmetricCipher::exportPublicKeyToPEM)
        .function("encrypt", &VirgilAsymmetricCipher::encrypt)
        .function("decrypt", &VirgilAsymmetricCipher::decrypt)
        .function("sign", &VirgilAsymmetricCipher::sign)
        .function("verify", &VirgilAsymmetricCipher::verify)
    ;


}

EMSCRIPTEN_BINDINGS(virgil_crypto_pfs) {
        class_<VirgilPFSSession>("VirgilPFSSession")
            .constructor<VirgilByteArray, VirgilByteArray, VirgilByteArray, VirgilByteArray>()
            .function("isEmpty", &VirgilPFSSession::isEmpty)
            .function("getIdentifier", &VirgilPFSSession::getIdentifier)
            .function("getEncryptionSecretKey", &VirgilPFSSession::getEncryptionSecretKey)
            .function("getDecryptionSecretKey", &VirgilPFSSession::getDecryptionSecretKey)
            .function("getAdditionalData", &VirgilPFSSession::getAdditionalData)
        ;

        class_<VirgilPFSPublicKey>("VirgilPFSPublicKey")
            .constructor<>()
            .constructor<VirgilByteArray>()
            .function("isEmpty", &VirgilPFSPublicKey::isEmpty)
            .function("getKey", &VirgilPFSPublicKey::getKey)
        ;

        class_<VirgilPFSPrivateKey>("VirgilPFSPrivateKey")
            .constructor<>()
            .constructor<VirgilByteArray>()
            .constructor<VirgilByteArray, VirgilByteArray>()
            .function("isEmpty", &VirgilPFSPrivateKey::isEmpty)
            .function("getKey", &VirgilPFSPrivateKey::getKey)
            .function("getPassword", &VirgilPFSPrivateKey::getPassword)
        ;

        class_<VirgilPFSEncryptedMessage>("VirgilPFSEncryptedMessage")
            .constructor<VirgilByteArray, VirgilByteArray, VirgilByteArray>()
            .function("getSessionIdentifier", &VirgilPFSEncryptedMessage::getSessionIdentifier)
            .function("getSalt", &VirgilPFSEncryptedMessage::getSalt)
            .function("getCipherText", &VirgilPFSEncryptedMessage::getCipherText)
        ;

        class_<VirgilPFSInitiatorPublicInfo>("VirgilPFSInitiatorPublicInfo")
            .constructor<VirgilPFSPublicKey, VirgilPFSPublicKey>()
            .function("getIdentityPublicKey", &VirgilPFSInitiatorPublicInfo::getIdentityPublicKey)
            .function("getEphemeralPublicKey", &VirgilPFSInitiatorPublicInfo::getEphemeralPublicKey)
        ;

        class_<VirgilPFSInitiatorPrivateInfo>("VirgilPFSInitiatorPrivateInfo")
            .constructor<VirgilPFSPrivateKey, VirgilPFSPrivateKey>()
            .function("getIdentityPrivateKey", &VirgilPFSInitiatorPrivateInfo::getIdentityPrivateKey)
            .function("getEphemeralPrivateKey", &VirgilPFSInitiatorPrivateInfo::getEphemeralPrivateKey)
        ;

        class_<VirgilPFSResponderPublicInfo>("VirgilPFSResponderPublicInfo")
            .constructor<VirgilPFSPublicKey, VirgilPFSPublicKey>()
            .constructor<VirgilPFSPublicKey, VirgilPFSPublicKey, VirgilPFSPublicKey>()
            .function("getIdentityPublicKey", &VirgilPFSResponderPublicInfo::getIdentityPublicKey)
            .function("getLongTermPublicKey", &VirgilPFSResponderPublicInfo::getLongTermPublicKey)
            .function("getOneTimePublicKey", &VirgilPFSResponderPublicInfo::getOneTimePublicKey)
        ;

        class_<VirgilPFSResponderPrivateInfo>("VirgilPFSResponderPrivateInfo")
            .constructor<VirgilPFSPrivateKey, VirgilPFSPrivateKey>()
            .constructor<VirgilPFSPrivateKey, VirgilPFSPrivateKey, VirgilPFSPrivateKey>()
            .function("getIdentityPrivateKey", &VirgilPFSResponderPrivateInfo::getIdentityPrivateKey)
            .function("getLongTermPrivateKey", &VirgilPFSResponderPrivateInfo::getLongTermPrivateKey)
            .function("getOneTimePrivateKey", &VirgilPFSResponderPrivateInfo::getOneTimePrivateKey)
        ;

        class_<VirgilPFS>("VirgilPFS")
            .constructor<>()
            .function("startInitiatorSession", &VirgilPFS::startInitiatorSession)
            .function("startResponderSession", &VirgilPFS::startResponderSession)
            .function("encrypt", &VirgilPFS::encrypt)
            .function("decrypt", &VirgilPFS::decrypt)
            .function("getSession", &VirgilPFS::getSession)
            .function("setSession", &VirgilPFS::setSession)
        ;
}
