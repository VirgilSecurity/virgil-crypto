#include <virgil/service/data/VirgilUniqueTicketType.h>

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <string>
#include <sstream>
#include <map>

class UniqueTicketTypeConverter {
private:
public:
    UniqueTicketTypeConverter() {
        toString_[VirgilUniqueTicketType_Email] = "email";
        toString_[VirgilUniqueTicketType_Phone] = "phone";
        toString_[VirgilUniqueTicketType_Fax] = "fax";
        toString_[VirgilUniqueTicketType_Domain] = "domain";
        toString_[VirgilUniqueTicketType_MacAddress] = "mac_address";
        toString_[VirgilUniqueTicketType_Application] = "application";

        std::map<VirgilUniqueTicketType, std::string>::const_iterator toStringIt = toString_.begin();
        for (; toStringIt != toString_.end(); ++toStringIt) {
            toType_[toStringIt->second] = toStringIt->first;
        }
    }

    VirgilUniqueTicketType operator()(const std::string& name) const {
        std::map<std::string, VirgilUniqueTicketType>::const_iterator it = toType_.find(name);
        if (it == toType_.end()) {
            std::ostringstream message;
            message << "VirgilUniqueTicketType: cannot find type for given name: " << name << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }

    std::string operator()(VirgilUniqueTicketType type) const {
        std::map<VirgilUniqueTicketType, std::string>::const_iterator it = toString_.find(type);
        if (it == toString_.end()) {
            std::ostringstream message;
            message << "VirgilUniqueTicketType: cannot find name for given type: " << type << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }
private:
    std::map<VirgilUniqueTicketType, std::string> toString_;
    std::map<std::string, VirgilUniqueTicketType> toType_;
};

static const UniqueTicketTypeConverter gUniqueTicketTypeConverter;

std::string virgil_unique_ticket_type_to_string(VirgilUniqueTicketType type) {
    return gUniqueTicketTypeConverter(type);
}

VirgilUniqueTicketType virgil_unique_ticket_type_from_string(const std::string type) {
    return gUniqueTicketTypeConverter(type);
}

