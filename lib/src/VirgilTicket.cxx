#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/data/VirgilUserIdTicket.h>
using virgil::service::data::VirgilUserIdTicket;

#include <virgil/service/data/VirgilUserInfoTicket.h>
using virgil::service::data::VirgilUserInfoTicket;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

VirgilTicket::~VirgilTicket() throw() {}

bool VirgilTicket::isUserIdTicket() const { return false; }

VirgilUserIdTicket& VirgilTicket::asUserIdTicket() {
    if (!isUserIdTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserIdTicket.");
    }
    return dynamic_cast<VirgilUserIdTicket&>(*this);
}

const VirgilUserIdTicket& VirgilTicket::asUserIdTicket() const {
    if (!isUserIdTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserIdTicket.");
    }
    return dynamic_cast<const VirgilUserIdTicket&>(*this);
}

bool VirgilTicket::isUserInfoTicket() const { return false; }

VirgilUserInfoTicket& VirgilTicket::asUserInfoTicket() {
    if (!isUserInfoTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserInfoTicket.");
    }
    return dynamic_cast<VirgilUserInfoTicket&>(*this);
}

const VirgilUserInfoTicket& VirgilTicket::asUserInfoTicket() const {
    if (!isUserInfoTicket()) {
        throw VirgilException("Dynamic cast error from VirgilTicket to VirgilUserInfoTicket.");
    }
    return dynamic_cast<const VirgilUserInfoTicket&>(*this);
}
