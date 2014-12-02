#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

VirgilSign::VirgilSign(const VirgilByteArray& hashName, const VirgilByteArray& signedDigest,
                const VirgilByteArray& signerCertificateId)
        : hashName_(hashName), signedDigest_(signedDigest), signerCertificateId_(signerCertificateId) {
}

VirgilSign::~VirgilSign() throw() {
}

VirgilByteArray VirgilSign::hashName() const {
    return hashName_;
}

VirgilByteArray VirgilSign::signedDigest() const {
    return signedDigest_;
}

VirgilByteArray VirgilSign::signerCertificateId() const {
    return signerCertificateId_;
}
