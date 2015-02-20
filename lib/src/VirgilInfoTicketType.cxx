#include <virgil/service/data/VirgilInfoTicketType.h>

#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <string>
#include <sstream>
#include <map>

class InfoTicketTypeConverter {
private:
public:
    InfoTicketTypeConverter() {
        toString_[VirgilInfoTicketType_FirstName] = "first_name";
        toString_[VirgilInfoTicketType_LastName] = "last_name";
        toString_[VirgilInfoTicketType_MiddleName] = "middle_name";
        toString_[VirgilInfoTicketType_Nickname] = "nickname";
        toString_[VirgilInfoTicketType_BirthDate] = "birth_date";

        std::map<VirgilInfoTicketType, std::string>::const_iterator toStringIt = toString_.begin();
        for (; toStringIt != toString_.end(); ++toStringIt) {
            toType_[toStringIt->second] = toStringIt->first;
        }
    }

    VirgilInfoTicketType operator()(const std::string& name) const {
        std::map<std::string, VirgilInfoTicketType>::const_iterator it = toType_.find(name);
        if (it == toType_.end()) {
            std::ostringstream message;
            message << "VirgilInfoTicketType: cannot find type for given name: " << name << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }

    std::string operator()(VirgilInfoTicketType type) const {
        std::map<VirgilInfoTicketType, std::string>::const_iterator it = toString_.find(type);
        if (it == toString_.end()) {
            std::ostringstream message;
            message << "VirgilInfoTicketType: cannot find name for given type: " << type << ".";
            throw VirgilException(message.str());
        }
        return it->second;
    }
private:
    std::map<VirgilInfoTicketType, std::string> toString_;
    std::map<std::string, VirgilInfoTicketType> toType_;
};

static const InfoTicketTypeConverter gInfoTicketTypeConverter;


std::string virgil_info_ticket_type_to_string(VirgilInfoTicketType type) {
    return gInfoTicketTypeConverter(type);
}

VirgilInfoTicketType virgil_info_ticket_type_from_string(const std::string type) {
    return gInfoTicketTypeConverter(type);
}

