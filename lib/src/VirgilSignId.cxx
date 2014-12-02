#include "virgil/service/data/VirgilSignId.h"
using virgil::service::data::VirgilSignId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

VirgilByteArray VirgilSignId::signId() const {
    return signId_;
}

void VirgilSignId::setSignId(const VirgilByteArray& signId) {
    signId_ = signId;
}
