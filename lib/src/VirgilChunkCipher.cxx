/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <virgil/service/VirgilChunkCipher.h>
using virgil::service::VirgilChunkCipher;

#include <cstring>
#include <cmath>

#include <string>
using std::string;

#include <sstream>
using std::ostringstream;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/VirgilException.h>
using virgil::VirgilException;

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

class VirgilChunkCipherImpl {
public:
    VirgilChunkCipherImpl(const VirgilByteArray& moduleName)
            : random(moduleName), symmetricCipher(VirgilSymmetricCipher::aes256()),
              iv(symmetricCipher.ivSize(), 0x00) {
    }
public:
    VirgilRandom random;
    VirgilSymmetricCipher symmetricCipher;
    VirgilByteArray iv;
    VirgilByteArray encryptionKey;
};

}}

VirgilChunkCipher::VirgilChunkCipher() : impl_(0) {
    const char * moduleName = "virgil::service::VirgilChunkCipher";
    impl_ = new VirgilChunkCipherImpl(
            VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN((const unsigned char *)moduleName, strlen(moduleName)));
}

VirgilChunkCipher::~VirgilChunkCipher() throw() {
    if (impl_) {
        delete impl_;
    }
}

size_t VirgilChunkCipher::adjustEncryptionChunkSize(size_t preferredChunkSize) const {
    size_t blockSize = impl_->symmetricCipher.blockSize();
    if (preferredChunkSize < blockSize) {
        return blockSize - 1;
    } else {
        return (size_t)(preferredChunkSize / blockSize) * blockSize - 1;
    }
}

size_t VirgilChunkCipher::adjustDecryptionChunkSize(size_t encryptionChunkSize) const {
    size_t blockSize = impl_->symmetricCipher.blockSize();
    return (size_t)ceil((double)encryptionChunkSize / blockSize) * blockSize;
}

VirgilByteArray VirgilChunkCipher::startEncryption(const VirgilByteArray& publicKey) {
    impl_->encryptionKey = impl_->random.randomize(impl_->symmetricCipher.keyLength());
    impl_->symmetricCipher.clear();
    impl_->symmetricCipher.setEncryptionKey(impl_->encryptionKey);
    impl_->symmetricCipher.setPadding(kSymmetricCipher_Padding);
    impl_->symmetricCipher.reset();

    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPublicKey(publicKey);
    return asymmetricCipher.encrypt(impl_->encryptionKey);
}

void VirgilChunkCipher::startDecryption(const VirgilByteArray& encryptionKey, const VirgilByteArray& privateKey,
                const VirgilByteArray& privateKeyPassword) {
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::none();
    asymmetricCipher.setPrivateKey(privateKey, privateKeyPassword);

    impl_->encryptionKey = asymmetricCipher.decrypt(encryptionKey);
    impl_->symmetricCipher.clear();
    impl_->symmetricCipher.setDecryptionKey(impl_->encryptionKey);
    impl_->symmetricCipher.setPadding(kSymmetricCipher_Padding);
    impl_->symmetricCipher.reset();
}

VirgilByteArray VirgilChunkCipher::process(const VirgilByteArray& data) {
    bool dataIsAlignedToBlockSize = (data.size() % impl_->symmetricCipher.blockSize()) == 0;
    if (impl_->symmetricCipher.isDecryptionMode() && !dataIsAlignedToBlockSize) {
        ostringstream message;
        message << "In the decryption mode data size MUST be multiple of ";
        message << impl_->symmetricCipher.blockSize() << " bytes.";
        throw VirgilException(message.str());
    }
    return impl_->symmetricCipher.crypt(data, impl_->iv);
}

void VirgilChunkCipher::finalize() {
    impl_->symmetricCipher.clear();
    VIRGIL_BYTE_ARRAY_ZEROIZE(impl_->encryptionKey);
}
