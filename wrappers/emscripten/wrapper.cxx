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

#include <virgil/crypto/asn1/VirgilAsn1Compatible.h>

#include <virgil/crypto/VirgilHash.h>
#include <virgil/crypto/VirgilBase64.h>
#include <virgil/crypto/VirgilCustomParams.h>

#include <virgil/service/data/VirgilJsonCompatible.h>
#include <virgil/service/data/VirgilId.h>
#include <virgil/service/data/VirgilAccountId.h>
#include <virgil/service/data/VirgilCertificateId.h>
#include <virgil/service/data/VirgilTicketId.h>
#include <virgil/service/data/VirgilSignId.h>
#include <virgil/service/data/VirgilAccount.h>
#include <virgil/service/data/VirgilCertificate.h>
#include <virgil/service/data/VirgilTicket.h>
#include <virgil/service/data/VirgilUniqueTicket.h>
#include <virgil/service/data/VirgilUniqueTicketType.h>
#include <virgil/service/data/VirgilInfoTicket.h>
#include <virgil/service/data/VirgilInfoTicketType.h>
#include <virgil/service/data/VirgilSign.h>
#include <virgil/service/data/VirgilKeyPair.h>

#include <virgil/service/VirgilCipherBase.h>
#include <virgil/service/VirgilCipher.h>
#include <virgil/service/VirgilSigner.h>

namespace virgil {

static std::string VirgilException_what(const virgil::VirgilException& exception) {
    return std::string(exception.what());
}

val VirgilByteArray_data(VirgilByteArray& data) {
    return val(internal::toWireType(typed_memory_view(data.size(), data.data())));
}

void VirgilByteArray_assign(VirgilByteArray& byteArray, val data) {
    byteArray = vecFromJSArray<VirgilByteArray::value_type>(data);
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
}

EMSCRIPTEN_BINDINGS(virgil_crypto_asn1) {
    class_<virgil::crypto::asn1::VirgilAsn1Compatible>("VirgilAsn1Compatible")
        .function("toAsn1", &virgil::crypto::asn1::VirgilAsn1Compatible::toAsn1)
        .function("fromAsn1", &virgil::crypto::asn1::VirgilAsn1Compatible::fromAsn1)
    ;
}

EMSCRIPTEN_BINDINGS(virgil_crypto) {
    class_<virgil::crypto::VirgilHash, base<virgil::crypto::asn1::VirgilAsn1Compatible>>("VirgilHash")
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

    class_<virgil::crypto::VirgilCustomParams, base<virgil::crypto::asn1::VirgilAsn1Compatible>>("VirgilCustomParams")
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

template<typename VirgilIdProviderType>
struct VirgilIdProviderAccess {
    static std::shared_ptr<typename VirgilIdProviderType::value_type> id(VirgilIdProviderType& idProvider) {
        return std::shared_ptr<typename VirgilIdProviderType::value_type>(&idProvider.id());
    }

    static void setId(VirgilIdProviderType& idProvider, const typename VirgilIdProviderType::value_type& id) {
        idProvider.setId(id);
    }
};

template<typename ID>
class_<virgil::service::data::VirgilIdProvider<ID>, base<virgil::service::data::VirgilJsonCompatible>>
        register_VirgilIdProvider(const char* name) {
    typedef virgil::service::data::VirgilIdProvider<ID> IdProviderType;

    return class_<virgil::service::data::VirgilIdProvider<ID>, base<virgil::service::data::VirgilJsonCompatible>>(name)
        .function("id", VirgilIdProviderAccess<IdProviderType>::id)
        .function("setId", VirgilIdProviderAccess<IdProviderType>::setId)
        ;
}

namespace virgil { namespace service { namespace data {

static std::unique_ptr<VirgilTicket> VirgilTicket_createFromAsn1(const VirgilByteArray& asn1) {
    return std::unique_ptr<VirgilTicket>(VirgilTicket::createFromAsn1(asn1));
}

static std::unique_ptr<VirgilTicket> VirgilTicket_createFromJson(const VirgilByteArray& json) {
    return std::unique_ptr<VirgilTicket>(VirgilTicket::createFromJson(json));
}

static std::shared_ptr<VirgilUniqueTicket> VirgilTicket_asUniqueTicket(VirgilTicket& ticket) {
    return std::shared_ptr<VirgilUniqueTicket>(&ticket.asUniqueTicket());
}

static std::shared_ptr<VirgilInfoTicket> VirgilTicket_asInfoTicket(VirgilTicket& ticket) {
    return std::shared_ptr<VirgilInfoTicket>(&ticket.asInfoTicket());
}

}}}

EMSCRIPTEN_BINDINGS(virgil_service_data) {
    class_<virgil::service::data::VirgilJsonCompatible, base<virgil::crypto::asn1::VirgilAsn1Compatible>>("VirgilJsonCompatible")
        .function("toJson", &virgil::service::data::VirgilJsonCompatible::toJson)
        .function("fromJson", &virgil::service::data::VirgilJsonCompatible::fromJson)
    ;

    class_<virgil::service::data::VirgilId, base<virgil::service::data::VirgilJsonCompatible>>("VirgilId")
        .function("isEmpty", &virgil::service::data::VirgilId::isEmpty)
        .function("clear", &virgil::service::data::VirgilId::clear)
    ;

    class_<virgil::service::data::VirgilAccountId, base<virgil::service::data::VirgilId>>("VirgilAccountId")
        .constructor<>()
        .function("accountId", &virgil::service::data::VirgilAccountId::accountId)
        .function("setAccountId", &virgil::service::data::VirgilAccountId::setAccountId)
    ;

    class_<virgil::service::data::VirgilCertificateId, base<virgil::service::data::VirgilAccountId>>("VirgilCertificateId")
        .constructor<>()
        .function("certificateId", &virgil::service::data::VirgilCertificateId::certificateId)
        .function("setCertificateId", &virgil::service::data::VirgilCertificateId::setCertificateId)
    ;

    class_<virgil::service::data::VirgilTicketId, base<virgil::service::data::VirgilCertificateId>>("VirgilTicketId")
        .constructor<>()
        .function("ticketId", &virgil::service::data::VirgilTicketId::ticketId)
        .function("setTicketId", &virgil::service::data::VirgilTicketId::setTicketId)
    ;

    class_<virgil::service::data::VirgilSignId, base<virgil::service::data::VirgilTicketId>>("VirgilSignId")
        .constructor<>()
        .function("signId", &virgil::service::data::VirgilSignId::signId)
        .function("setSignId", &virgil::service::data::VirgilSignId::setSignId)
    ;

    register_VirgilIdProvider<VirgilAccountId>("VirgilAccountIdProvider");
    class_<virgil::service::data::VirgilAccount, base<virgil::service::data::VirgilIdProvider<VirgilAccountId>>>("VirgilAccount")
        .constructor<>()
    ;

    register_VirgilIdProvider<VirgilCertificateId>("VirgilCertificateIdProvider");
    class_<virgil::service::data::VirgilCertificate, base<virgil::service::data::VirgilIdProvider<VirgilCertificateId>>>("VirgilCertificate")
        .constructor<>()
        .constructor<const virgil::VirgilByteArray&>()
        .function("publicKey", &virgil::service::data::VirgilCertificate::publicKey)
    ;

    register_VirgilIdProvider<VirgilTicketId>("VirgilTicketIdProvider");
    class_<virgil::service::data::VirgilTicket, base<virgil::service::data::VirgilIdProvider<VirgilTicketId>>>("VirgilTicket")
        .class_function("createFromAsn1", &virgil::service::data::VirgilTicket_createFromAsn1)
        .class_function("createFromJson", &virgil::service::data::VirgilTicket_createFromJson)
        .function("isUniqueTicket", &virgil::service::data::VirgilTicket::isUniqueTicket)
        .function("isUniqueTicket", &virgil::service::data::VirgilTicket_asUniqueTicket)
        .function("isUniqueTicket", &virgil::service::data::VirgilTicket::isInfoTicket)
        .function("isUniqueTicket", &virgil::service::data::VirgilTicket_asInfoTicket)
    ;

    enum_<VirgilUniqueTicketType>("VirgilUniqueTicketType")
        .value("None", VirgilUniqueTicketType_None)
        .value("Email", VirgilUniqueTicketType_Email)
        .value("Phone", VirgilUniqueTicketType_Phone)
        .value("Fax", VirgilUniqueTicketType_Fax)
        .value("Domain", VirgilUniqueTicketType_Domain)
        .value("MacAddress", VirgilUniqueTicketType_MacAddress)
        .value("Application", VirgilUniqueTicketType_Application)
    ;

    class_<virgil::service::data::VirgilUniqueTicket, base<virgil::service::data::VirgilTicket>>("VirgilUniqueTicket")
        .constructor<>()
        .constructor<VirgilUniqueTicketType, const virgil::VirgilByteArray&>()
        .function("type", &virgil::service::data::VirgilUniqueTicket::type)
        .function("value", &virgil::service::data::VirgilUniqueTicket::value)
    ;

    enum_<VirgilInfoTicketType>("VirgilInfoTicketType")
        .value("None", VirgilInfoTicketType_None)
        .value("FirstName", VirgilInfoTicketType_FirstName)
        .value("LastName", VirgilInfoTicketType_LastName)
        .value("MiddleName", VirgilInfoTicketType_MiddleName)
        .value("Nickname", VirgilInfoTicketType_Nickname)
        .value("BirthDate", VirgilInfoTicketType_BirthDate)
    ;

    class_<virgil::service::data::VirgilInfoTicket, base<virgil::service::data::VirgilTicket>>("VirgilInfoTicket")
        .constructor<>()
        .constructor<VirgilInfoTicketType, const virgil::VirgilByteArray&>()
        .function("type", &virgil::service::data::VirgilInfoTicket::type)
        .function("value", &virgil::service::data::VirgilInfoTicket::value)
    ;

    register_VirgilIdProvider<VirgilSignId>("VirgilSignIdProvider");
    class_<virgil::service::data::VirgilSign, base<virgil::service::data::VirgilIdProvider<VirgilSignId>>>("VirgilSign")
        .constructor<>()
        .constructor<const virgil::VirgilByteArray&, const virgil::VirgilByteArray&, const virgil::VirgilByteArray&>()
        .function("hashName", &virgil::service::data::VirgilSign::hashName)
        .function("signedDigest", &virgil::service::data::VirgilSign::signedDigest)
        .function("signerCertificateId", &virgil::service::data::VirgilSign::signerCertificateId)
    ;

    class_<virgil::service::data::VirgilKeyPair>("VirgilKeyPair")
        .constructor<>()
        .constructor<const VirgilByteArray&>()
        .constructor<const VirgilByteArray&, const VirgilByteArray&>()
        .function("publicKey", &virgil::service::data::VirgilKeyPair::publicKey)
        .function("privateKey", &virgil::service::data::VirgilKeyPair::privateKey)
    ;
}

namespace virgil { namespace service {
    static std::shared_ptr<crypto::VirgilCustomParams> VirgilCipherBase_customParams(VirgilCipherBase& cipher) {
        return std::shared_ptr<crypto::VirgilCustomParams>(&cipher.customParams());
    }

    static VirgilSign VirgilSigner_sign_1(VirgilSigner& signer, const VirgilByteArray& data,
            const VirgilByteArray& signerCertificateId,
            const VirgilByteArray& privateKey) {
        return signer.sign(data, signerCertificateId, privateKey);
    }

    static VirgilSign VirgilSigner_sign_2(VirgilSigner& signer, const VirgilByteArray& data,
            const VirgilByteArray& signerCertificateId,
            const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
        return signer.sign(data, signerCertificateId, privateKey, privateKeyPassword);
    }

    static bool VirgilSigner_verify(VirgilSigner& signer, const VirgilByteArray& data,
            const VirgilSign& sign, const VirgilByteArray& publicKey) {
        return signer.verify(data, sign, publicKey);
    }

    static VirgilSign VirgilSigner_signAsn1_1(VirgilSigner& signer, const VirgilAsn1Compatible& asn1,
            const VirgilByteArray& signerCertificateId, const VirgilByteArray& privateKey) {
        return signer.sign(asn1, signerCertificateId, privateKey);
    }

    static VirgilSign VirgilSigner_signAsn1_2(VirgilSigner& signer, const VirgilAsn1Compatible& asn1,
            const VirgilByteArray& signerCertificateId,
            const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword = VirgilByteArray()) {
        return signer.sign(asn1, signerCertificateId, privateKey, privateKeyPassword);
    }

    static bool VirgilSigner_verifyAsn1(VirgilSigner& signer, const VirgilAsn1Compatible& asn1,
            const VirgilSign& sign, const VirgilByteArray& publicKey) {
        return signer.verify(asn1, sign, publicKey);
    }

}}

EMSCRIPTEN_BINDINGS(virgil_service) {
    class_<virgil::service::VirgilCipherBase>("VirgilCipherBase")
        .function("addKeyRecipient", &virgil::service::VirgilCipherBase::addKeyRecipient)
        .function("removeKeyRecipient", &virgil::service::VirgilCipherBase::removeKeyRecipient)
        .function("addPasswordRecipient", &virgil::service::VirgilCipherBase::addPasswordRecipient)
        .function("removePasswordRecipient", &virgil::service::VirgilCipherBase::removePasswordRecipient)
        .function("removeAllRecipients", &virgil::service::VirgilCipherBase::removeAllRecipients)
        .function("getContentInfo", &virgil::service::VirgilCipherBase::getContentInfo)
        .function("setContentInfo", &virgil::service::VirgilCipherBase::setContentInfo)
        .function("customParams", &virgil::service::VirgilCipherBase_customParams)
    ;

    class_<virgil::service::VirgilCipher, base<virgil::service::VirgilCipherBase>>("VirgilCipher")
        .constructor<>()
        .function("encrypt", &virgil::service::VirgilCipher::encrypt)
        .function("decryptWithKey", &virgil::service::VirgilCipher::decryptWithKey)
        .function("decryptWithPassword", &virgil::service::VirgilCipher::decryptWithPassword)
    ;

    class_<virgil::service::VirgilSigner>("VirgilSigner")
        .constructor<>()
        .constructor<const virgil::crypto::VirgilHash&>()
        .function("sign", &virgil::service::VirgilSigner_sign_1)
        .function("sign", &virgil::service::VirgilSigner_sign_2)
        .function("verify", &virgil::service::VirgilSigner_verify)
        .function("signAsn1", &virgil::service::VirgilSigner_signAsn1_1)
        .function("signAsn1", &virgil::service::VirgilSigner_signAsn1_2)
        .function("verifyAsn1", &virgil::service::VirgilSigner_verifyAsn1)
    ;
}
