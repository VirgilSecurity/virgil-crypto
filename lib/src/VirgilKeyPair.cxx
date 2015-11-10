/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#include <virgil/crypto/VirgilKeyPair.h>

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilRandom.h>
#include <virgil/crypto/foundation/VirgilKeyPairGenerator.h>
#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::foundation::VirgilKeyPairGenerator;
using virgil::crypto::foundation::VirgilAsymmetricCipher;

/**
 * @name Configuration constants.
 */
///@{
static const VirgilKeyPairGenerator::ECKeyGroup kKeyPair_ECKeyGroup = VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1;
///@}

VirgilKeyPair VirgilKeyPair::ecNist192(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecNist224(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecNist256(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecNist384(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP384R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecNist521(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP521R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecBrainpool256(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_BP256R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecBrainpool384(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_BP384R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecBrainpool512(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecKoblitz192(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192K1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecKoblitz224(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224K1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::ecKoblitz256(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::ec();
    cipher.genKeyPair(VirgilKeyPairGenerator::ec(VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256K1));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::rsa256(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::rsa();
    cipher.genKeyPair(VirgilKeyPairGenerator::rsa(256));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::rsa512(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::rsa();
    cipher.genKeyPair(VirgilKeyPairGenerator::rsa(512));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::rsa1024(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::rsa();
    cipher.genKeyPair(VirgilKeyPairGenerator::rsa(1024));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::rsa2048(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::rsa();
    cipher.genKeyPair(VirgilKeyPairGenerator::rsa(2048));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}

VirgilKeyPair VirgilKeyPair::rsa4096(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher cipher = VirgilAsymmetricCipher::rsa();
    cipher.genKeyPair(VirgilKeyPairGenerator::rsa(4096));
    return VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM(pwd));
}


VirgilKeyPair::VirgilKeyPair(const VirgilByteArray& pwd) {
    VirgilAsymmetricCipher asymmetricCipher = VirgilAsymmetricCipher::ec();
    asymmetricCipher.genKeyPair(VirgilKeyPairGenerator::ec(kKeyPair_ECKeyGroup));
    publicKey_ = asymmetricCipher.exportPublicKeyToPEM();
    privateKey_ = asymmetricCipher.exportPrivateKeyToPEM(pwd);
}

VirgilKeyPair::VirgilKeyPair(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey)
        : publicKey_(publicKey), privateKey_(privateKey) {
};

VirgilByteArray VirgilKeyPair::publicKey() const {
    return publicKey_;
}

VirgilByteArray VirgilKeyPair::privateKey() const {
    return privateKey_;
}

