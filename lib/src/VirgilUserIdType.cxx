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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <map>
#include <string>
#include <sstream>

static const char * const kUserIdTypeName_Email = "email";
static const char * const kUserIdTypeName_Phone = "phone";
static const char * const kUserIdTypeName_Fax = "fax";
static const char * const kUserIdTypeName_Domain = "domain";
static const char * const kUserIdTypeName_MacAddress = "mac_address";
static const char * const kUserIdTypeName_Application = "application";

class UserIdConverter {
private:
    typedef std::map<VirgilUserIdType::Code, std::string> CodeToStringType;
    typedef std::map<std::string, VirgilUserIdType::Code> StringToCodeType;
public:
    UserIdConverter() {
        toString_[VirgilUserIdType::EmailCode] = kUserIdTypeName_Email;
        toString_[VirgilUserIdType::PhoneCode] = kUserIdTypeName_Phone;
        toString_[VirgilUserIdType::FaxCode] = kUserIdTypeName_Fax;
        toString_[VirgilUserIdType::DomainCode] = kUserIdTypeName_Domain;
        toString_[VirgilUserIdType::MacAddressCode] = kUserIdTypeName_MacAddress;
        toString_[VirgilUserIdType::ApplicationCode] = kUserIdTypeName_Application;

        toCode_[kUserIdTypeName_Email] = VirgilUserIdType::EmailCode;
        toCode_[kUserIdTypeName_Phone] = VirgilUserIdType::PhoneCode;
        toCode_[kUserIdTypeName_Fax] = VirgilUserIdType::FaxCode;
        toCode_[kUserIdTypeName_Domain] = VirgilUserIdType::DomainCode;
        toCode_[kUserIdTypeName_MacAddress] = VirgilUserIdType::MacAddressCode;
        toCode_[kUserIdTypeName_Application] = VirgilUserIdType::ApplicationCode;
    }

    VirgilUserIdType::Code operator()(const std::string& name) const {
        StringToCodeType::const_iterator it = toCode_.find(name);
        if (it == toCode_.end()) {
            std::ostringstream message;
            message << "VirgilUserIdType: cannot find code for given name: " << name << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }

    std::string operator()(VirgilUserIdType::Code code) const {
        CodeToStringType::const_iterator it = toString_.find(code);
        if (it == toString_.end()) {
            std::ostringstream message;
            message << "VirgilUserIdType: cannot find name for given code: " << code << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }
private:
    CodeToStringType toString_;
    StringToCodeType toCode_;
};

static const UserIdConverter userIdConverter_;

const VirgilUserIdType VirgilUserIdType::email =
        VirgilUserIdType::typeFromCode(VirgilUserIdType::EmailCode);
const VirgilUserIdType VirgilUserIdType::phone =
        VirgilUserIdType::typeFromCode(VirgilUserIdType::PhoneCode);
const VirgilUserIdType VirgilUserIdType::fax =
        VirgilUserIdType::typeFromCode(VirgilUserIdType::FaxCode);
const VirgilUserIdType VirgilUserIdType::domain =
        VirgilUserIdType::typeFromCode(VirgilUserIdType::DomainCode);
const VirgilUserIdType VirgilUserIdType::macAddress =
        VirgilUserIdType::typeFromCode(VirgilUserIdType::MacAddressCode);
const VirgilUserIdType VirgilUserIdType::application =
        VirgilUserIdType::typeFromCode(VirgilUserIdType::ApplicationCode);

VirgilUserIdType VirgilUserIdType::typeFromCode(VirgilUserIdType::Code code) {
    return VirgilUserIdType(userIdConverter_(code), code);
}

VirgilUserIdType VirgilUserIdType::typeFromName(const std::string& name) {
    return VirgilUserIdType(name, userIdConverter_(name));
}

VirgilUserIdType::VirgilUserIdType(const std::string& name, VirgilUserIdType::Code code)
        : name_(name), code_(code) {
}

std::string VirgilUserIdType::name() const {
    return name_;
}

VirgilUserIdType::Code VirgilUserIdType::code() const {
    return code_;
}

bool VirgilUserIdType::isEmail() const {
    return *this == VirgilUserIdType::email;
}

bool VirgilUserIdType::isPhone() const {
    return *this == VirgilUserIdType::phone;
}

bool VirgilUserIdType::isFax() const {
    return *this == VirgilUserIdType::fax;
}

bool VirgilUserIdType::isMacAddress() const {
    return *this == VirgilUserIdType::macAddress;
}

bool VirgilUserIdType::isDomain() const {
    return *this == VirgilUserIdType::domain;
}

bool VirgilUserIdType::isApplication() const {
    return *this == VirgilUserIdType::application;
}

bool operator==(const VirgilUserIdType& lhs, const VirgilUserIdType& rhs) {
    return lhs.code() == rhs.code();
}
