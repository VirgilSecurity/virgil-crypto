#include <virgil/service/data/marshalling/VirgilJsonDataMarshaller.h>
using virgil::service::data::marshalling::VirgilJsonDataMarshaller;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;

#include <virgil/service/data/VirgilAccount.h>
using virgil::service::data::VirgilAccount;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

#include <virgil/service/data/VirgilUserIdTicket.h>
using virgil::service::data::VirgilUserIdTicket;

#include <virgil/service/data/VirgilUserInfoTicket.h>
using virgil::service::data::VirgilUserInfoTicket;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

#include <iostream>
using std::endl;

#include <string>
using std::string;

#include <sstream>
using std::ostringstream;
using std::istringstream;

#include <json/json.h>

/**
 * @name Json Keys
 */
///@{
static const char * const kKey_Id = "id";
static const char * const kKey_AccountId = "account_id";
static const char * const kKey_CertificateId = "certificate_id";
static const char * const kKey_TicketId = "ticket_id";
static const char * const kKey_SignId = "sign_id";
static const char * const kKey_SignedDigest = "signed_digest";
static const char * const kKey_HashName = "hash_name";
static const char * const kKey_SignerCertificateId = "signer_certificate_id";
static const char * const kKey_PublicKey = "public_key";

static const char * const kKey_Ticket_Type = "type";
static const char * const kKey_Ticket_Data = "data";
static const char * const kKey_Ticket_Data_UserId = "user_id";
static const char * const kKey_Ticket_Data_UserIdType = "user_id_type";
static const char * const kKey_Ticket_Data_UserFirstName = "user_first_name";
static const char * const kKey_Ticket_Data_UserLastName = "user_last_name";
static const char * const kKey_Ticket_Data_UserAge = "user_age";

static const char * const kValue_Ticket_Type_UserId = "user_id_ticket";
static const char * const kValue_Ticket_Type_UserInfo = "user_info_ticket";
///@}

static std::string jsonValueTypeToString_(Json::ValueType jsonType) {
    switch (jsonType) {
        case Json::intValue:
            return "Integer";
        case Json::uintValue:
            return "Unsigned";
        case Json::realValue:
            return "Real";
        case Json::stringValue:
            return "String";
        case Json::booleanValue:
            return "Boolean";
        case Json::arrayValue:
            return "Array";
        case Json::objectValue:
            return "Object";
        case Json::nullValue:
        default:
            return "Null";
    }
}

template<Json::ValueType valueType>
static Json::Value jsonGetValue_(const Json::Value& json, const char * key) {
    Json::Value value = json[key];
    if (value.type() != valueType) {
        throw VirgilException(std::string() +
                "Expected Json " + jsonValueTypeToString_(valueType) + " value under key: '" + key +
                "', but found " + jsonValueTypeToString_(value.type()) + " value.");
    }
    return value;
}

static std::string jsonGetString_(const Json::Value json, const char * key) {
    return jsonGetValue_<Json::stringValue>(json, key).asString();
}

static VirgilByteArray jsonGetStringAsByteArray_(const Json::Value json, const char * key) {
    return VIRGIL_BYTE_ARRAY_FROM_STD_STRING(jsonGetString_(json, key));
}

static Json::Value jsonWriteRawData_(const VirgilByteArray& data) {
    return Json::Value(VirgilBase64::encode(data));
}

static VirgilByteArray jsonReadRawData_(const Json::Value& json, const char * key) {
    return VirgilBase64::decode(jsonGetString_(json, key));
}

static void jsonWriteAccountId_(const VirgilAccountId& id, Json::Value& jsonId) {
    jsonId[kKey_AccountId] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(id.accountId());
}

static void jsonWriteCertificateId_(const VirgilCertificateId& id, Json::Value& jsonId) {
    jsonWriteAccountId_(id, jsonId);
    jsonId[kKey_CertificateId] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(id.certificateId());
}

static void jsonWriteTicketId_(const VirgilTicketId& id, Json::Value& jsonId) {
    jsonWriteCertificateId_(id, jsonId);
    jsonId[kKey_TicketId] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(id.ticketId());
}

static void jsonWriteSignId_(const VirgilSignId& id, Json::Value& jsonId) {
    jsonWriteTicketId_(id, jsonId);
    jsonId[kKey_SignId] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(id.signId());
}

static Json::Value jsonWriteAccount_(const VirgilAccount& account) {
    Json::Value jsonId(Json::objectValue);
    jsonWriteAccountId_(account.id(), jsonId);
    Json::Value jsonRoot(Json::objectValue);
    jsonRoot[kKey_Id] = jsonId;
    return jsonRoot;
}

static Json::Value jsonWriteCertificate_(const VirgilCertificate& certificate) {
    Json::Value jsonId(Json::objectValue);
    jsonWriteCertificateId_(certificate.id(), jsonId);
    Json::Value jsonRoot(Json::objectValue);
    jsonRoot[kKey_Id] = jsonId;
    jsonRoot[kKey_PublicKey] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(certificate.publicKey());
    return jsonRoot;
}

static Json::Value jsonWriteTicketData_(const VirgilUserIdTicket& ticket) {
    Json::Value jsonRoot(Json::objectValue);
    jsonRoot[kKey_Ticket_Data_UserId] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(ticket.userId());
    jsonRoot[kKey_Ticket_Data_UserIdType] = ticket.userIdType().name();
    return jsonRoot;
}

static Json::Value jsonWriteTicketData_(const VirgilUserInfoTicket& ticket) {
    Json::Value jsonRoot(Json::objectValue);
    jsonRoot[kKey_Ticket_Data_UserFirstName] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(ticket.userFirstName());
    jsonRoot[kKey_Ticket_Data_UserLastName] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(ticket.userLastName());
    jsonRoot[kKey_Ticket_Data_UserAge] = (Json::UInt)ticket.userAge();
    return jsonRoot;
}


static Json::Value jsonWriteTicket_(const VirgilTicket& ticket) {
    Json::Value jsonId(Json::objectValue);
    jsonWriteTicketId_(ticket.id(), jsonId);
    Json::Value jsonRoot(Json::objectValue);
    jsonRoot[kKey_Id] = jsonId;
    if (ticket.isUserIdTicket()) {
        jsonRoot[kKey_Ticket_Type] = kValue_Ticket_Type_UserId;
        jsonRoot[kKey_Ticket_Data] = jsonWriteTicketData_(ticket.asUserIdTicket());
    } else if (ticket.isUserInfoTicket()) {
        jsonRoot[kKey_Ticket_Type] = kValue_Ticket_Type_UserInfo;
        jsonRoot[kKey_Ticket_Data] = jsonWriteTicketData_(ticket.asUserInfoTicket());
    }
    return jsonRoot;
}

static Json::Value jsonWriteSign_(const VirgilSign& sign) {
    Json::Value jsonId(Json::objectValue);
    jsonWriteSignId_(sign.id(), jsonId);
    Json::Value jsonRoot(Json::objectValue);
    jsonRoot[kKey_Id] = jsonId;
    jsonRoot[kKey_HashName] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(sign.hashName());
    jsonRoot[kKey_SignedDigest] = jsonWriteRawData_(sign.signedDigest());
    jsonRoot[kKey_SignerCertificateId] = VIRGIL_BYTE_ARRAY_TO_STD_STRING(sign.signerCertificateId());
    return jsonRoot;
}

static void jsonReadAccountId_(const Json::Value& jsonId, VirgilAccountId& accountId) {
    accountId.setAccountId(jsonGetStringAsByteArray_(jsonId, kKey_AccountId));
}

static void jsonReadCertificateId_(const Json::Value& jsonId, VirgilCertificateId& certificateId) {
    jsonReadAccountId_(jsonId, certificateId);
    certificateId.setCertificateId(jsonGetStringAsByteArray_(jsonId, kKey_CertificateId));
}

static void jsonReadTicketId_(const Json::Value& jsonId, VirgilTicketId& ticketId) {
    jsonReadCertificateId_(jsonId, ticketId);
    ticketId.setTicketId(jsonGetStringAsByteArray_(jsonId, kKey_TicketId));
}

static void jsonReadSignId_(const Json::Value& jsonId, VirgilSignId& signId) {
    jsonReadTicketId_(jsonId, signId);
    signId.setSignId(jsonGetStringAsByteArray_(jsonId, kKey_SignId));
}

static VirgilAccount * jsonReadAccount_(const Json::Value& jsonRoot) {
    Json::Value jsonId = jsonGetValue_<Json::objectValue>(jsonRoot, kKey_Id);
    VirgilAccount *account = new VirgilAccount();
    jsonReadAccountId_(jsonId, account->id());
    return account;
}

static VirgilCertificate * jsonReadCertificate_(const Json::Value& jsonRoot) {
    VirgilCertificate *certificate = new VirgilCertificate(jsonGetStringAsByteArray_(jsonRoot, kKey_PublicKey));
    Json::Value jsonId = jsonGetValue_<Json::objectValue>(jsonRoot, kKey_Id);
    jsonReadCertificateId_(jsonId, certificate->id());
    return certificate;
}

static VirgilUserIdTicket * jsonReadUserIdTicket_(const Json::Value& jsonRoot) {
    Json::Value jsonData = jsonGetValue_<Json::objectValue>(jsonRoot, kKey_Ticket_Data);

    VirgilUserIdTicket * ticket =
            new VirgilUserIdTicket(jsonGetStringAsByteArray_(jsonData, kKey_Ticket_Data_UserId),
            VirgilUserIdType::typeFromName(jsonGetString_(jsonData, kKey_Ticket_Data_UserIdType)));

    Json::Value jsonId = jsonGetValue_<Json::objectValue>(jsonRoot, kKey_Id);
    jsonReadTicketId_(jsonId, ticket->id());
    return ticket;
}

static VirgilUserInfoTicket * jsonReadUserInfoTicket_(const Json::Value& jsonRoot) {
    Json::Value jsonData = jsonGetValue_<Json::objectValue>(jsonRoot, kKey_Ticket_Data);

    VirgilUserInfoTicket * ticket = new VirgilUserInfoTicket(
            jsonGetStringAsByteArray_(jsonData, kKey_Ticket_Data_UserFirstName),
            jsonGetStringAsByteArray_(jsonData, kKey_Ticket_Data_UserLastName),
            jsonGetValue_<Json::intValue>(jsonData, kKey_Ticket_Data_UserAge).asUInt()
        );

    Json::Value jsonId = jsonGetValue_<Json::objectValue>(jsonRoot, kKey_Id);
    jsonReadTicketId_(jsonId, ticket->id());
    return ticket;
}

static VirgilTicket * jsonReadTicket_(const Json::Value& jsonRoot) {
    string ticketType = jsonGetString_(jsonRoot, kKey_Ticket_Type);
    if (ticketType == string(kValue_Ticket_Type_UserId)) {
        return jsonReadUserIdTicket_(jsonRoot);
    } else if (ticketType == string(kValue_Ticket_Type_UserInfo)) {
        return jsonReadUserInfoTicket_(jsonRoot);
    }
    return new VirgilTicket();
}

static VirgilSign * jsonReadSign_(const Json::Value& jsonRoot) {
    VirgilByteArray jsonHashName = jsonGetStringAsByteArray_(jsonRoot, kKey_HashName);
    VirgilByteArray signedDigest = jsonReadRawData_(jsonRoot, kKey_SignedDigest);
    VirgilByteArray jsonCertificateId = jsonGetStringAsByteArray_(jsonRoot, kKey_SignerCertificateId);

    VirgilSign *sign = new VirgilSign(jsonHashName, signedDigest, jsonCertificateId);

    Json::Value jsonId = jsonRoot[kKey_Id];
    if (jsonId.type() == Json::objectValue) {
        jsonReadSignId_(jsonId, sign->id());
    }
    return sign;
}

static Json::Value parseJson_(const VirgilByteArray& data) {
    Json::Reader reader(Json::Features::strictMode());
    Json::Value jsonRoot;
    if (!reader.parse(VIRGIL_BYTE_ARRAY_TO_STD_STRING(data), jsonRoot)) {
        throw VirgilException(reader.getFormattedErrorMessages());
    }
    return jsonRoot;
}

VirgilByteArray VirgilJsonDataMarshaller::marshal(const VirgilAccount& account) {
    Json::Value json = jsonWriteAccount_(account);
    return VIRGIL_BYTE_ARRAY_FROM_STD_STRING(Json::StyledWriter().write(json));
}

VirgilAccount * VirgilJsonDataMarshaller::demarshalAccount(const VirgilByteArray& data) {
    Json::Value jsonRoot = parseJson_(data);
    return jsonReadAccount_(jsonRoot);
}

VirgilByteArray VirgilJsonDataMarshaller::marshal(const VirgilCertificate& certificate) {
    Json::Value json = jsonWriteCertificate_(certificate);
    return VIRGIL_BYTE_ARRAY_FROM_STD_STRING(Json::StyledWriter().write(json));
}

VirgilCertificate * VirgilJsonDataMarshaller::demarshalCertificate(const VirgilByteArray& data) {
    Json::Value jsonRoot = parseJson_(data);
    return jsonReadCertificate_(jsonRoot);
}

VirgilByteArray VirgilJsonDataMarshaller::marshal(const VirgilTicket& ticket) {
    Json::Value json = jsonWriteTicket_(ticket);
    return VIRGIL_BYTE_ARRAY_FROM_STD_STRING(Json::StyledWriter().write(json));
}

VirgilTicket * VirgilJsonDataMarshaller::demarshalTicket(const VirgilByteArray& data) {
    Json::Value jsonRoot = parseJson_(data);
    return jsonReadTicket_(jsonRoot);
}

VirgilByteArray VirgilJsonDataMarshaller::marshal(const VirgilSign& sign) {
    Json::Value json = jsonWriteSign_(sign);
    return VIRGIL_BYTE_ARRAY_FROM_STD_STRING(Json::StyledWriter().write(json));
}

VirgilSign * VirgilJsonDataMarshaller::demarshalSign(const VirgilByteArray& data) {
    Json::Value jsonRoot = parseJson_(data);
    return jsonReadSign_(jsonRoot);
}

