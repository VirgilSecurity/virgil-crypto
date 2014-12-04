#include <virgil/service/VirgilMultipartCipher.h>
using virgil::service::VirgilMultipartCipher;

#include <cstring>

#include <string>
using std::string;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

#include <virgil/crypto/VirgilRandom.h>
using virgil::crypto::VirgilRandom;

#include <virgil/crypto/VirgilKDF.h>
using virgil::crypto::VirgilKDF;

#include <virgil/crypto/VirgilSymmetricCipher.h>
using virgil::crypto::VirgilSymmetricCipher;

#include <virgil/crypto/VirgilKeyPairGenerator.h>
using virgil::crypto::VirgilKeyPairGenerator;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

/**
 * @name Configuration constants.
 */
///@{
static const VirgilKeyPairGenerator::ECKeyGroup kKeyPair_ECKeyGroup =
        VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1;
static const VirgilSymmetricCipher::VirgilSymmetricCipherPadding kSymmetricCipher_Padding =
        VirgilSymmetricCipher::VirgilSymmetricCipherPadding_PKCS7;
///@}

namespace virgil { namespace service {

class VirgilMultipartCipherImpl {
public:
    VirgilMultipartCipherImpl(const VirgilByteArray& moduleName)
            : random(moduleName), symmetricCipher(VirgilSymmetricCipher::aes256()), encryptionKey(), publicKey() {
    }
public:
    VirgilRandom random;
    VirgilSymmetricCipher symmetricCipher;
    VirgilByteArray encryptionKey;
    VirgilByteArray publicKey;
};

}}

VirgilMultipartCipher::VirgilMultipartCipher() : impl_(0) {
    const char * moduleName = "virgil::service::VirgilMultipartCipher";
    impl_ = new VirgilMultipartCipherImpl(
            VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN((const unsigned char *)moduleName, strlen(moduleName)));
}

VirgilMultipartCipher::~VirgilMultipartCipher() throw() {
    if (impl_) {
        delete impl_;
    }
}

VirgilByteArray VirgilMultipartCipher::startEncryption(const VirgilByteArray& publicKey) {
    impl_->publicKey = publicKey;
    impl_->encryptionKey = impl_->random.randomize(impl_->symmetricCipher.keyLength());
    impl_->symmetricCipher.clear();
    impl_->symmetricCipher.setEncryptionKey(impl_->encryptionKey);
    impl_->symmetricCipher.setPadding(kSymmetricCipher_Padding);
    impl_->symmetricCipher.reset();

    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPublicKey(impl_->publicKey);
    return asymmetricCipher.encrypt(impl_->encryptionKey);
}

void VirgilMultipartCipher::startDecryption(const VirgilByteArray& encryptionKey, const VirgilByteArray& privateKey,
                const VirgilByteArray& privateKeyPassword) {
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPrivateKey(privateKey, privateKeyPassword);

    impl_->encryptionKey = asymmetricCipher.decrypt(encryptionKey);
    impl_->symmetricCipher.clear();
    impl_->symmetricCipher.setDecryptionKey(impl_->encryptionKey);
    impl_->symmetricCipher.setPadding(kSymmetricCipher_Padding);
    impl_->symmetricCipher.reset();
}

VirgilByteArray VirgilMultipartCipher::process(const VirgilByteArray& data) {
    return impl_->symmetricCipher.update(data);
}

VirgilByteArray VirgilMultipartCipher::finish() {
    VirgilByteArray lastData = impl_->symmetricCipher.finish();
    impl_->symmetricCipher.clear();
    return lastData;
}
