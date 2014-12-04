#include <virgil/service/VirgilCipher.h>
using virgil::service::VirgilCipher;

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

class VirgilCipherImpl {
public:
    VirgilCipherImpl(const VirgilByteArray& moduleName) : random(moduleName) {}
public:
    VirgilRandom random;
};

}}

VirgilCipher::VirgilCipher() : impl_(0) {
    const char * moduleName = "virgil::service::VirgilCipher";
    impl_ = new VirgilCipherImpl(
            VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN((const unsigned char *)moduleName, strlen(moduleName)));
}

VirgilCipher::~VirgilCipher() throw() {
    if (impl_) {
        delete impl_;
    }
}

VirgilKeyPair VirgilCipher::generateKeyPair(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::ec();
    asymmetricCipher.genKeyPair(VirgilKeyPairGenerator::ec(kKeyPair_ECKeyGroup));
    VirgilByteArray publicKey = asymmetricCipher.exportPublicKeyToPEM();
    VirgilByteArray privateKey = asymmetricCipher.exportPrivateKeyToPEM(pwd);
    return VirgilKeyPair(publicKey, privateKey);
}

VirgilByteArray VirgilCipher::encrypt(VirgilDataSource& source, VirgilDataSink& sink,
        const VirgilByteArray& publicKey) {

    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();

    VirgilByteArray encryptionKey = impl_->random.randomize(symmetricCipher.keyLength());
    symmetricCipher.setEncryptionKey(encryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    while (source.hasData() && sink.isGood()) {
        sink.write(symmetricCipher.update(source.read()));
    }
    if (sink.isGood()) {
        sink.write(symmetricCipher.finish());
    }

    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPublicKey(publicKey);
    return asymmetricCipher.encrypt(encryptionKey);
}

void VirgilCipher::decrypt(VirgilDataSource& source, VirgilDataSink& sink,
        const VirgilByteArray& encryptionKey,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {

    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPrivateKey(privateKey, privateKeyPassword);

    VirgilByteArray decryptionKey = asymmetricCipher.decrypt(encryptionKey);

    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();
    symmetricCipher.setDecryptionKey(decryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    while (source.hasData() && sink.isGood()) {
        sink.write(symmetricCipher.update(source.read()));
    }
    if (sink.isGood()) {
        sink.write(symmetricCipher.finish());
    }
}

VirgilByteArray VirgilCipher::encryptWithPassword(const VirgilByteArray& data, const VirgilByteArray& pwd) {
    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();

    VirgilByteArray encryptionKey = VirgilKDF::kdf1(pwd, symmetricCipher.keyLength());
    symmetricCipher.setEncryptionKey(encryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    VirgilByteArray firstChunk = symmetricCipher.update(data);
    VirgilByteArray secondChunk = symmetricCipher.finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), secondChunk.begin(), secondChunk.end());
    return result;
}

VirgilByteArray VirgilCipher::decryptWithPassword(const VirgilByteArray& data, const VirgilByteArray& pwd) {
    VirgilSymmetricCipher symmetricCipher = VirgilSymmetricCipher::aes256();

    VirgilByteArray decryptionKey = VirgilKDF::kdf1(pwd, symmetricCipher.keyLength());
    symmetricCipher.setDecryptionKey(decryptionKey);
    symmetricCipher.setPadding(kSymmetricCipher_Padding);
    symmetricCipher.reset();
    VirgilByteArray firstChunk = symmetricCipher.update(data);
    VirgilByteArray secondChunk = symmetricCipher.finish();

    VirgilByteArray result;
    result.insert(result.end(), firstChunk.begin(), firstChunk.end());
    result.insert(result.end(), secondChunk.begin(), secondChunk.end());
    return result;
}
