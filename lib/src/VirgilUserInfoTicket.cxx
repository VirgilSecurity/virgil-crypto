#include <virgil/service/data/VirgilUserInfoTicket.h>
using virgil::service::data::VirgilUserInfoTicket;

#include <cstddef>

VirgilUserInfoTicket::VirgilUserInfoTicket
        (const VirgilByteArray& userFirstName, const VirgilByteArray& userLastName, size_t userAge)
        : userFirstName_(userFirstName), userLastName_(userLastName), userAge_(userAge) {
}

VirgilUserInfoTicket::~VirgilUserInfoTicket() throw() {
}

bool VirgilUserInfoTicket::isUserInfoTicket() const {
    return true;
}

VirgilByteArray VirgilUserInfoTicket::userFirstName() const {
    return userFirstName_;
}

VirgilByteArray VirgilUserInfoTicket::userLastName() const {
    return userLastName_;
}

size_t VirgilUserInfoTicket::userAge() const {
    return userAge_;
}
