#include "virgil/service/data/VirgilAccountId.h"
using virgil::service::data::VirgilAccountId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

VirgilByteArray VirgilAccountId::accountId() const {
    return accountId_;
}

void VirgilAccountId::setAccountId(const VirgilByteArray& accountId) {
    accountId_ = accountId;
}
