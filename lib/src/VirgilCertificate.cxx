#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

VirgilCertificate::VirgilCertificate(const VirgilByteArray& publicKey) : publicKey_(publicKey) {
}

VirgilByteArray VirgilCertificate::publicKey() const {
    return publicKey_;
}

VirgilCertificate::~VirgilCertificate() throw() {
}
