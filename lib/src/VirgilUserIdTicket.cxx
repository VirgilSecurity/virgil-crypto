#include <virgil/service/data/VirgilUserIdTicket.h>
using virgil::service::data::VirgilUserIdTicket;

#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

VirgilUserIdTicket::VirgilUserIdTicket(const VirgilByteArray& userId, const VirgilUserIdType& userIdType)
        : userId_(userId), userIdType_(userIdType) {}

VirgilUserIdTicket::~VirgilUserIdTicket() throw() {}

VirgilByteArray VirgilUserIdTicket::userId() const { return userId_; }

const VirgilUserIdType& VirgilUserIdTicket::userIdType() const { return userIdType_; }

bool VirgilUserIdTicket::isUserIdTicket() const { return true; }
