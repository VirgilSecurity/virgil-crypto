#include <virgil/service/VirgilSigner.h>
using virgil::service::VirgilSigner;

#include <cstring>

#include <string>
using std::string;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

#include <virgil/service/stream/VirgilDataSource.h>
using virgil::service::stream::VirgilDataSource;

#include <virgil/service/stream/VirgilDataSink.h>
using virgil::service::stream::VirgilDataSink;

#include <virgil/service/data/marshalling/VirgilAsn1DataMarshaller.h>
using virgil::service::data::marshalling::VirgilAsn1DataMarshaller;

#include <virgil/crypto/VirgilHash.h>
using virgil::crypto::VirgilHash;

#include <virgil/crypto/VirgilAsymmetricCipher.h>
using virgil::crypto::VirgilAsymmetricCipher;

VirgilSigner::VirgilSigner() {
}

VirgilSigner::~VirgilSigner() throw() {
}

VirgilSign VirgilSigner::sign(VirgilDataSource& source, const VirgilByteArray& signerCertificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilHash hash = VirgilHash::sha256();
    hash.start();
    while (source.hasData()) {
        hash.update(source.read());
    }
    VirgilByteArray digest = hash.finish();

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    VirgilByteArray sign = cipher.sign(digest);

    return VirgilSign(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(hash.name()), sign, signerCertificateId);
}

bool VirgilSigner::verify(VirgilDataSource& source, const VirgilSign& sign, const VirgilByteArray& publicKey) {
    VirgilHash hash = VirgilHash::withName(sign.hashName());
    hash.start();
    while (source.hasData()) {
        hash.update(source.read());
    }
    VirgilByteArray digest = hash.finish();

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPublicKey(publicKey);
    return cipher.verify(digest, sign.signedDigest());
}

VirgilSign VirgilSigner::sign(VirgilTicket& ticket, const VirgilByteArray& signerCertificateId,
        const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword) {
    VirgilHash hash = VirgilHash::sha256();

    VirgilAsn1DataMarshaller marshaller;
    VirgilByteArray digest = hash.hash(marshaller.marshal(ticket));

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPrivateKey(privateKey, privateKeyPassword);
    VirgilByteArray sign = cipher.sign(digest);

    return VirgilSign(VIRGIL_BYTE_ARRAY_FROM_STD_STRING(hash.name()), sign, signerCertificateId);
}

bool VirgilSigner::verify(VirgilTicket& ticket, const VirgilSign& sign, const VirgilByteArray& publicKey) {
    VirgilHash hash = VirgilHash::withName(sign.hashName());

    VirgilAsn1DataMarshaller marshaller;
    VirgilByteArray digest = hash.hash(marshaller.marshal(ticket));

    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::none();
    cipher.setPublicKey(publicKey);
    return cipher.verify(digest, sign.signedDigest());
}

