#include "virgil/service/data/VirgilCertificateId.h"
using virgil::service::data::VirgilCertificateId;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

VirgilByteArray VirgilCertificateId::certificateId() const {
    return certificateId_;
}

void VirgilCertificateId::setCertificateId(const VirgilByteArray& certificateId) {
    certificateId_ = certificateId;
}
