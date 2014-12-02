#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

VirgilKeyPair::VirgilKeyPair(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey)
    : publicKey_(publicKey), privateKey_(privateKey) {};

VirgilByteArray VirgilKeyPair::publicKey() const {
    return publicKey_;
}

VirgilByteArray VirgilKeyPair::privateKey() const {
    return privateKey_;
}

