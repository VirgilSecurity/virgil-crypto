#include "virgil/service/data/VirgilTicketId.h"
using virgil::service::data::VirgilTicketId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

VirgilByteArray VirgilTicketId::ticketId() const {
    return ticketId_;
}

void VirgilTicketId::setTicketId(const VirgilByteArray& ticketId) {
    ticketId_ = ticketId;
}
