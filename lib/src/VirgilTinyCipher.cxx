/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#include <virgil/crypto/VirgilTinyCipher.h>

#include <map>
#include <cmath>

#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilKDF.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>
#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <virgil/crypto/internal/utils.h>


using virgil::crypto::VirgilTinyCipher;
using virgil::crypto::VirgilTinyCipherImpl;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::make_error;

using virgil::crypto::foundation::VirgilAsymmetricCipher;
using virgil::crypto::foundation::VirgilSymmetricCipher;
using virgil::crypto::foundation::VirgilKDF;
using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;


static const unsigned char kPackageCount_Max = 0x0F; ///< Defines maximum package count

constexpr VirgilHash::Algorithm kHashAlgorithm_Default = VirgilHash::Algorithm::SHA384;

using PackageMap = std::map<size_t, VirgilByteArray>; ///< { PackageNo -> PackageData }

/**
 *
 * Master package:
 *
 *     |--------|----------------------|-------------|---------|
 *     | header | ephemeral public key | sender sign | payload |
 *     |--------|----------------------|-------------|---------|
 *
 * Master package legend:
 *
 *     * header - master package header;
 *     * ephemeral public key - public key with eliminated crypto agility;
 *     * sender sign - sign of the encrypted data that was made with sender's private key;
 *     * payload - chunk of the encrypted data.
 *
 * Master package header - 1 byte of the packed data:
 *
 *     |-----------|-----------|-----------------|---------------|
 *     | is master | is signed | public key code | package count |
 *     |-----------|-----------|-----------------|---------------|
 *     |0         0|1         1|2               3|4             7|
 *     |-----------|-----------|-----------------|---------------|
 *     |   1 bit   |   1 bit   |     2 bits      |    4 bits     |
 *     |-----------|-----------|-----------------|---------------|
 *
 * Master package header legend:
 *
 *     * is master - defines that given package is a master package: 0 - data package, 1 - master package;
 *     * is signed - defines that given package contains encrypted data sign: 0 - does not contain, 1 - contains;
 *     * public key code:
 *         - 00 - Curve25519;
 *         - 01 - not defined / not supported;
 *         - 10 - not defined / not supported;
 *         - 11 - not defined / not supported, possible 'extended package' meaning will be used in the future.
 *     * package count - total package count (including master package).
 *
 *
 * Data package:
 *
 *     |--------|----------------------------------------------|
 *     | header | payload                                      |
 *     |--------|----------------------------------------------|
 *
 * Data package legend:
 *
 *     * header - data package header;
 *     * payload - chunk of the encrypted data.
 *
 * Data package header - 1 byte of the packed data:
 *
 *     |-----------|----------------------------|----------------|
 *     | is master |           unused           | package number |
 *     |-----------|----------------------------|----------------|
 *     |0         0|1                          3|4              7|
 *     |-----------|----------------------------|----------------|
 *     |   1 bit   |           3 bits           |     4 bits     |
 *     |-----------|----------------------------|----------------|
 *
 * Data package header legend:
 *
 *     * is master - defines that given package is a master package: 0 - data package, 1 - master package;
 *     * unused - unused bits, correspond information stored in the master package.
 *     * package number - index number of the current package.
 */

/**
 * @brief Transform given authentication code of AEAD ciphers to the input vector of given length.
 *
 * @param data - additional authenticated data
 * @param ivSize - length of the input vector to be derived
 *
 * @return Derived input vector
 */
static VirgilByteArray auth_to_iv(const VirgilByteArray& data, size_t ivSize);

/**
 * @brief Return package count based on the given parameters.
 *
 * @param dataSize - size of the data to be packed
 * @param packageSize - maximum size of the one package
 * @param publicKeySize - size of the ephemeral public key to be packed
 * @param signSize - size of the ephemeral public key to be packed
 *
 * @return Calculated package count.
 */
static size_t calc_package_count(size_t dataSize, size_t packageSize, size_t publicKeySize, size_t signSize);

/**
 * @brief Return payload of the master package.
 *
 * Master package is a special package that contains some service data in conjunction with user payload,
 *     as so user payload has limited length, that should be calculated dynamically.
 *
 * @param packageSize - maximum size of the one package
 * @param publicKeySize - size of the ephemeral public key to be packed
 * @param signSize - size of the ephemeral public key to be packed
 *
 * @return Payload length in the master package.
 */
static size_t calc_master_package_payload_size(size_t packageSize, size_t publicKeySize, size_t signSize);

/**
 * @brief Produce additional authenticated data for AEAD cipher.
 *
 * @param packageCount- package count
 * @param ephemeralContext - asymmetric cipher context that handles ephemeral public key
 * @param isSigned - defines that package is signed
 */
static VirgilByteArray
        make_auth_data(size_t packageCount, const VirgilAsymmetricCipher& ephemeralContext, bool isSigned);

/**
 * @brief Read header from the package and parse it.
 *
 * @param[inout] packageIt - current parse position in the package
 * @param[in] end - end of the package
 * @param[out] isMaster - defines that package is master
 * @param[out] isSigned - defines that package is signed
 * @param[out] pkCode - ephemeral public key code
 * @param[out] packageCount - package count
 */
static void read_package_header(
        VirgilByteArray::const_iterator& packageIt, VirgilByteArray::const_iterator end, bool* isMaster,
        bool* isSigned, unsigned char* pkCode, size_t* packageCount);

/**
 * @brief Read sign bits from the package.
 *
 * @param packageIt - current parse position in the package
 * @param end - end of the package
 * @param signLength - expected sign length
 */
static VirgilByteArray read_package_sign_bits
        (VirgilByteArray::const_iterator& packageIt, VirgilByteArray::const_iterator end, size_t signLength);

/**
 * @brief Read ephemeral public key from the package.
 *
 * @param packageIt - current parse position in the package
 * @param end - end of the package
 * @param pkCode - ephemeral public key code
 */
static VirgilByteArray read_package_ephemeral_public_key
        (VirgilByteArray::const_iterator& packageIt, VirgilByteArray::const_iterator end, unsigned char pkCode);

/**
 * @brief Pack given parameters to the package header.
 *
 * @param isMaster - defines that package is master
 * @param isSigned - defines that package is signed
 * @param pkCode - ephemeral public key code
 * @param packageCount - package count
 *
 * @return Packed header
 */
static unsigned char write_package_header(bool isMaster, bool isSigned, unsigned char pkCode, size_t packageCount);

/**
 * @brief Return sign size according to the given public key code.
 *
 * @param pkCode - public key code
 * @return Sign length in bytes
 */
static size_t get_sign_size(unsigned char pkCode);

/**
 * @brief Return sign size according to the given public key type.
 *
 * @param pkType - public key type
 * @return Sign length in bytes
 */
static size_t get_sign_size(VirgilKeyPair::Type pkType);

/**
 * @brief Return public key size according to the given public key code.
 *
 * @param pkCode - public key code
 * @return Public key size in bytes
 */
static size_t get_public_key_size(unsigned char pkCode);

/**
 * @brief Return public key size according to the given public key type.
 *
 * @param pkType - public key type
 * @return Public key size in bytes
 */
static size_t get_public_key_size(VirgilKeyPair::Type pkType);

/**
 * @brief Convert public key type to the public key code.
 */
static unsigned char pk_type_to_code(VirgilKeyPair::Type pkType);

/**
 * @brief Convert public key code to the public key type.
 */
static VirgilKeyPair::Type pk_type_from_code(unsigned char pkCode);

/**
 * @brief Create cipher for common symmetric crypto operations.
 */
static VirgilSymmetricCipher create_shared_cipher();

class VirgilTinyCipher::Impl {
public:
    size_t packageSize = 0;
    size_t packageCount = 0;
    PackageMap packageMap;
    VirgilByteArray packageSignBits;
    VirgilByteArray ephemeralPublicKey;
};

VirgilTinyCipher::VirgilTinyCipher(size_t packageSize) : impl_(std::make_unique<Impl>()) {
    if (packageSize < PackageSize_Min) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Given package size less then minimum value required.");
    }
    impl_->packageSize = packageSize;
}

VirgilTinyCipher::VirgilTinyCipher(VirgilTinyCipher&& rhs) noexcept = default;

VirgilTinyCipher& VirgilTinyCipher::operator=(VirgilTinyCipher&& rhs) noexcept = default;

VirgilTinyCipher::~VirgilTinyCipher() noexcept = default;

void VirgilTinyCipher::reset() {
    impl_->packageMap.clear();
}

size_t VirgilTinyCipher::getPackageCount() const {
    return impl_->packageMap.size();
}

VirgilByteArray VirgilTinyCipher::getPackage(size_t index) const {
    PackageMap::const_iterator found = impl_->packageMap.find(index);
    if (found != impl_->packageMap.end()) {
        return found->second;
    } else {
        throw make_error(VirgilCryptoError::InvalidArgument, "Requested package is not found.");
    }
}

void VirgilTinyCipher::addPackage(const VirgilByteArray& package) {
    bool is_master = false;
    bool is_signed = false;
    unsigned char pk_type = 0;
    size_t package_no = 0;
    VirgilByteArray::const_iterator packageIt = package.begin();
    read_package_header(packageIt, package.end(), &is_master, &is_signed, &pk_type, &package_no);
    if (is_master) {
        impl_->packageCount = package_no;
        impl_->ephemeralPublicKey = read_package_ephemeral_public_key(packageIt, package.end(), pk_type);
        if (is_signed) {
            impl_->packageSignBits =
                    read_package_sign_bits(packageIt, package.end(), get_sign_size(pk_type));
        }
        package_no = 0; // number of master package is 0
    }
    impl_->packageMap[package_no] = VirgilByteArray(packageIt, package.end());
}

bool VirgilTinyCipher::isPackagesAccumulated() const {
    return (impl_->packageCount > 0) && (impl_->packageCount == impl_->packageMap.size());
}

void VirgilTinyCipher::encrypt(const VirgilByteArray& data, const VirgilByteArray& recipientPublicKey) {
    encryptAndSign(data, recipientPublicKey, VirgilByteArray());
}

void VirgilTinyCipher::encryptAndSign(
        const VirgilByteArray& data, const VirgilByteArray& recipientPublicKey,
        const VirgilByteArray& senderPrivateKey,
        const VirgilByteArray& senderPrivateKeyPassword) {

    // 1. Encrypt
    VirgilAsymmetricCipher recipientContext;
    recipientContext.setPublicKey(recipientPublicKey);

    VirgilAsymmetricCipher ephemeralContext;
    ephemeralContext.genKeyPairFrom(recipientContext);

    VirgilByteArray sharedSecret = VirgilAsymmetricCipher::computeShared(recipientContext, ephemeralContext);

    VirgilSymmetricCipher sharedCipher = create_shared_cipher();

    const bool doSign = !senderPrivateKey.empty();
    size_t signLength = doSign ? get_sign_size(ephemeralContext.getKeyType()) : 0;

    const size_t packageCount = calc_package_count(data.size() + sharedCipher.authTagLength(), impl_->packageSize,
            get_public_key_size(recipientContext.getKeyType()), signLength);

    if (packageCount > kPackageCount_Max) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Given data is too big to be encrypted.");
    }

    VirgilByteArray authData = make_auth_data(packageCount, ephemeralContext, doSign);

    sharedCipher.setEncryptionKey(sharedSecret);
    sharedCipher.setAuthData(authData);

    VirgilByteArray encryptedData = sharedCipher.crypt(data, auth_to_iv(authData, sharedCipher.ivSize()));

    // 2. Sign if requested
    VirgilByteArray signBits;
    if (doSign) {
        VirgilAsymmetricCipher senderContext;
        senderContext.setPrivateKey(senderPrivateKey, senderPrivateKeyPassword);

        VirgilHash hash(kHashAlgorithm_Default);
        VirgilByteArray digest = hash.hash(encryptedData);

        VirgilByteArray sign = senderContext.sign(digest, hash.type());
        signBits = senderContext.signToBits(sign);
    }

    // 3. Pack
    const unsigned char keyType = pk_type_to_code(ephemeralContext.getKeyType());
    const VirgilByteArray ephemeralPublicKeyBits = ephemeralContext.getPublicKeyBits();

    impl_->packageMap.clear();
    VirgilByteArray::const_iterator payloadIt = encryptedData.begin();
    for (size_t packageNo = 0; packageNo < packageCount; ++packageNo) {
        VirgilByteArray package;
        package.reserve(impl_->packageSize);
        const bool isMasterPackage = packageNo == 0;

        if (isMasterPackage) {
            package.push_back(write_package_header(isMasterPackage, doSign, keyType, packageCount));
            package.insert(package.end(), ephemeralPublicKeyBits.begin(), ephemeralPublicKeyBits.end());
            package.insert(package.end(), signBits.begin(), signBits.end());
        } else {
            package.push_back(write_package_header(isMasterPackage, false, keyType, packageNo));
        }

        if (package.size() > impl_->packageSize) {
            throw make_error(VirgilCryptoError::InvalidState, "Package size overflow.");
        }

        const size_t spaceLeft = impl_->packageSize - package.size();
        const std::ptrdiff_t payloadAvailable = encryptedData.end() - payloadIt;
        const size_t payloadSize = spaceLeft > payloadAvailable ? (size_t) payloadAvailable : spaceLeft;
        package.insert(package.end(), payloadIt, payloadIt + payloadSize);
        payloadIt += payloadSize;

        if (package.size() > impl_->packageSize) {
            throw make_error(VirgilCryptoError::InvalidState, "Package size overflow.");
        }

        impl_->packageMap[packageNo] = package;
    }

    // 4. Zeroize sensitive data
    VirgilByteArrayUtils::zeroize(sharedSecret);
    VirgilByteArrayUtils::zeroize(authData);
}

VirgilByteArray VirgilTinyCipher::decrypt(
        const VirgilByteArray& recipientPrivateKey, const VirgilByteArray& recipientPrivateKeyPassword) {
    return verifyAndDecrypt(VirgilByteArray(), recipientPrivateKey, recipientPrivateKeyPassword);
}

VirgilByteArray VirgilTinyCipher::verifyAndDecrypt(
        const VirgilByteArray& senderPublicKey,
        const VirgilByteArray& recipientPrivateKey,
        const VirgilByteArray& recipientPrivateKeyPassword) {

    if (!isPackagesAccumulated()) {
        throw make_error(VirgilCryptoError::InvalidState, "Not all packages was received.");
    }

    // 1. Configure contexts for asymmetric operations
    VirgilAsymmetricCipher recipientContext;
    recipientContext.setPrivateKey(recipientPrivateKey, recipientPrivateKeyPassword);

    VirgilAsymmetricCipher ephemeralContext;
    ephemeralContext.setPublicKey(impl_->ephemeralPublicKey);

    const bool doVerify = !senderPublicKey.empty();
    VirgilByteArray authData = make_auth_data(impl_->packageCount, ephemeralContext, doVerify);

    // 2. Verify data
    if (doVerify) {
        VirgilHash hash(kHashAlgorithm_Default);
        hash.start();
        for (PackageMap::const_iterator packageIt = impl_->packageMap.begin(); packageIt != impl_->packageMap.end();
             ++packageIt) {
            hash.update(packageIt->second);
        }
        VirgilByteArray digest = hash.finish();

        VirgilAsymmetricCipher senderContext;
        senderContext.setPublicKey(senderPublicKey);
        VirgilByteArray sign = senderContext.signFromBits(impl_->packageSignBits);

        if (!senderContext.verify(digest, sign, hash.type())) {
            throw make_error(VirgilCryptoError::MismatchSignature);
        }
    }

    // 3. Decrypt data
    VirgilByteArray sharedSecret = VirgilAsymmetricCipher::computeShared(ephemeralContext, recipientContext);

    VirgilSymmetricCipher sharedCipher = create_shared_cipher();

    sharedCipher.setDecryptionKey(sharedSecret);
    sharedCipher.setAuthData(authData);
    sharedCipher.setIV(auth_to_iv(authData, sharedCipher.ivSize()));
    sharedCipher.reset();

    VirgilByteArray decryptedData;
    for (PackageMap::const_iterator packageIt = impl_->packageMap.begin(); packageIt != impl_->packageMap.end();
         ++packageIt) {
        VirgilByteArray chunk = sharedCipher.update(packageIt->second);
        decryptedData.insert(decryptedData.end(), chunk.begin(), chunk.end());
    }
    VirgilByteArray lastChunk = sharedCipher.finish();
    decryptedData.insert(decryptedData.end(), lastChunk.begin(), lastChunk.end());

    // 4. Zeroize sensitive data
    VirgilByteArrayUtils::zeroize(sharedSecret);
    VirgilByteArrayUtils::zeroize(authData);

    return decryptedData;
}

static VirgilKeyPair::Type pk_type_from_code(unsigned char pkCode) {
    switch (pkCode) {
        case 0x00:
            return VirgilKeyPair::Type::EC_CURVE25519;
        case 0x01:
            return VirgilKeyPair::Type::EC_ED25519;
        default:
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}

static unsigned char pk_type_to_code(VirgilKeyPair::Type pkType) {
    switch (pkType) {
        case VirgilKeyPair::Type::EC_CURVE25519:
            return 0x00;
        case VirgilKeyPair::Type::EC_ED25519:
            return 0x01;
        default:
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}

static size_t get_public_key_size(VirgilKeyPair::Type pkType) {
    switch (pkType) {
        case VirgilKeyPair::Type::EC_CURVE25519:
        case VirgilKeyPair::Type::EC_ED25519:
            return 32;
        default:
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}

static size_t get_public_key_size(unsigned char pkCode) {
    return get_public_key_size(pk_type_from_code(pkCode));
}

static size_t get_sign_size(VirgilKeyPair::Type pkType) {
    switch (pkType) {
        case VirgilKeyPair::Type::EC_CURVE25519:
        case VirgilKeyPair::Type::EC_ED25519:
            return 64;
        default:
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
    }
}

static size_t get_sign_size(unsigned char pkCode) {
    return get_sign_size(pk_type_from_code(pkCode));
}

static unsigned char write_package_header(
        bool isMaster, bool isSigned, unsigned char pkCode, size_t packageCount) {
    if (packageCount > kPackageCount_Max) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Packages count greater then maximum allowed (15).");
    }

    unsigned char header = 0x0;
    if (isMaster) {
        header |= 0x80; // Set 1-st bit
    };
    if (isSigned) {
        header |= 0x40; // Set 2-nd bit
    }
    header |= (pkCode & 0x03) << 4; // Set bits: 3-4
    header |= (packageCount & 0x0F); // Set bits: 5-8

    return header;
}

static void read_package_header(
        VirgilByteArray::const_iterator& packageIt, VirgilByteArray::const_iterator end,
        bool* isMaster, bool* isSigned, unsigned char* pkCode, size_t* packageCount) {
    if (packageIt == end) {
        throw make_error(VirgilCryptoError::InvalidFormat, "No header in the package.");
    }
    unsigned char header = *packageIt++;
    *isMaster = (header & 0x80) != 0;
    *isSigned = (header & 0x40) != 0;
    *pkCode = (header >> 4) & (unsigned char) 0x03;
    *packageCount = header & (unsigned char) 0x0F;
}

static VirgilByteArray read_package_ephemeral_public_key(
        VirgilByteArray::const_iterator& packageIt, VirgilByteArray::const_iterator end, unsigned char pkCode) {

    VirgilAsymmetricCipher ephemeralPublicKeyContext;
    ephemeralPublicKeyContext.setKeyType(pk_type_from_code(pkCode));

    VirgilByteArray ephemeralPublicKeyBits;
    while (packageIt != end && ephemeralPublicKeyBits.size() < get_public_key_size(pkCode)) {
        ephemeralPublicKeyBits.push_back(*packageIt++);
    }

    if (ephemeralPublicKeyBits.size() != get_public_key_size(pkCode)) {
        throw make_error(VirgilCryptoError::InvalidFormat, "Ephemeral public key size mismatch.");
    }
    ephemeralPublicKeyContext.setPublicKeyBits(ephemeralPublicKeyBits);

    return ephemeralPublicKeyContext.exportPublicKeyToDER();
}

static VirgilByteArray read_package_sign_bits(
        VirgilByteArray::const_iterator& packageIt, VirgilByteArray::const_iterator end, size_t signLength) {
    VirgilByteArray signBits;
    while (packageIt != end && signBits.size() < signLength) {
        signBits.push_back(*packageIt++);
    }
    if (signBits.size() != signLength) {
        throw make_error(VirgilCryptoError::InvalidFormat, "Signature size mismatch.");
    }
    return signBits;
}

static VirgilByteArray make_auth_data(
        size_t packageCount, const VirgilAsymmetricCipher& ephemeralContext, bool isSigned) {
    if (packageCount > kPackageCount_Max) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Packages count greater then maximum allowed (15).");
    }
    VirgilByteArray authData;
    const VirgilByteArray ephemeralKey = ephemeralContext.getPublicKeyBits();
    authData.push_back(
            write_package_header(true, isSigned, pk_type_to_code(ephemeralContext.getKeyType()), packageCount));
    authData.insert(authData.end(), ephemeralKey.begin(), ephemeralKey.end());
    return authData;
}

static size_t calc_master_package_payload_size(size_t packageSize, size_t publicKeySize, size_t signSize) {
    const size_t masterPackageHeaderSize = 1 + publicKeySize + signSize;
    const size_t masterPackagePayloadSize = packageSize - masterPackageHeaderSize;
    return masterPackagePayloadSize;
}

static size_t calc_package_count(size_t dataSize, size_t packageSize, size_t publicKeySize, size_t signSize) {
    const size_t masterPackagePayloadSize = calc_master_package_payload_size(packageSize, publicKeySize, signSize);
    if (dataSize < masterPackagePayloadSize) {
        return 1;
    } else {
        return 1 + (size_t) (size_t) std::ceil(double(dataSize - masterPackagePayloadSize) / (packageSize - 1));
    }
}

static VirgilByteArray auth_to_iv(const VirgilByteArray& data, size_t ivSize) {
    return VirgilKDF(VirgilKDF::Algorithm::KDF2).derive(data, ivSize);
}

static VirgilSymmetricCipher create_shared_cipher() {
    return VirgilSymmetricCipher(VirgilSymmetricCipher::Algorithm::AES_256_GCM);
}
