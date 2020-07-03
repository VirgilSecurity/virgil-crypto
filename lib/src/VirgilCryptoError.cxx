/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <virgil/crypto/VirgilCryptoError.h>

using virgil::crypto::VirgilCryptoErrorCategory;

const char* VirgilCryptoErrorCategory::name() const noexcept {
    return "virgil/crypto";
}


std::string VirgilCryptoErrorCategory::message(int ev) const noexcept {
    switch (static_cast<VirgilCryptoError>(ev)) {
        case VirgilCryptoError::EmptyParameter:
            return "Given parameter is null or empty.";
        case VirgilCryptoError::ExceededMaxSize:
            return "Structure maximum size was exceeded.";
        case VirgilCryptoError::InvalidArgument:
            return "Argument given to a function is invalid. See function documentation.";
        case VirgilCryptoError::InvalidFormat:
            return "Data format is invalid. Given data may be malformed. See function documentation.";
        case VirgilCryptoError::InvalidPrivateKey:
            return "Invalid format of the Private Key.";
        case VirgilCryptoError::InvalidPrivateKeyPassword:
            return "Private Key password mismatch.";
        case VirgilCryptoError::InvalidPublicKey:
            return "Invalid format of the Public Key.";
        case VirgilCryptoError::InvalidSignature:
            return "Invalid format of the Signature.";
        case VirgilCryptoError::InvalidState:
            return "Function call prerequisite is broken.";
        case VirgilCryptoError::InvalidAuth:
            return "Invalid authentication. Data can be malformed.";
        case VirgilCryptoError::MismatchSignature:
            return "Signature validation failed.";
        case VirgilCryptoError::NotFoundKeyRecipient:
            return "Data was not encrypted for this recipient.";
        case VirgilCryptoError::NotFoundPasswordRecipient:
            return "Recipient with given password is not found.";
        case VirgilCryptoError::NotInitialized:
            return "Object is not initialized with specific algorithm, so can't be used.";
        case VirgilCryptoError::NotSecure:
            return "Security prerequisite is broken.";
        case VirgilCryptoError::UnsupportedAlgorithm:
            return "Algorithm is not supported in the current build.";
        default:
            return "Undefined error.";
    }
}

const VirgilCryptoErrorCategory& virgil::crypto::crypto_category() noexcept {
    static VirgilCryptoErrorCategory inst;
    return inst;
}
