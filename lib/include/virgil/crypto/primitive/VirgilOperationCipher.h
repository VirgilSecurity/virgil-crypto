/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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

#ifndef VIRGIL_CRYPTO_VIRGIL_SYMMETRIC_CIPHER_H
#define VIRGIL_CRYPTO_VIRGIL_SYMMETRIC_CIPHER_H

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil { namespace crypto { inline namespace primitive {

class VirgilOperationCipher {
private:
    template<class Impl>
    struct Model;;
public:
    template<class Impl>
    VirgilOperationCipher(Impl impl) : self_(std::make_shared<Model<Impl>>(std::move(impl))) {}

    size_t getKeySize() const {
        return self_->doGetKeySize();
    }

    size_t getNonceSize() const {
        return self_->doGetNonceSize();
    }

    VirgilByteArray encrypt(
            const VirgilByteArray& plainText, const VirgilByteArray& key, const VirgilByteArray& nonce,
            const VirgilByteArray& authData = VirgilByteArray()) const {

        return self_->doEncrypt(plainText, key, nonce, authData);
    }

    VirgilByteArray decrypt(
            const VirgilByteArray& plainText, const VirgilByteArray& key, const VirgilByteArray& nonce,
            const VirgilByteArray& authData = VirgilByteArray()) const {

        return self_->doDecrypt(plainText, key, nonce, authData);
    }

    static VirgilOperationCipher getDefault();

private:
    struct Concept {
        virtual size_t doGetKeySize() const = 0;

        virtual size_t doGetNonceSize() const = 0;

        virtual VirgilByteArray doEncrypt(
                const VirgilByteArray& plainText, const VirgilByteArray& key, const VirgilByteArray& nonce,
                const VirgilByteArray& authData) const = 0;

        virtual VirgilByteArray doDecrypt(
                const VirgilByteArray& plainText, const VirgilByteArray& key, const VirgilByteArray& nonce,
                const VirgilByteArray& authData) const = 0;
    };

    template<class Impl>
    struct Model : Concept {

        explicit Model(Impl impl) : impl_(std::move(impl)) {}

        size_t doGetKeySize() const override {
            return impl_.getKeySize();
        }

        size_t doGetNonceSize() const override {
            return impl_.getNonceSize();
        }

        VirgilByteArray doEncrypt(
                const VirgilByteArray& plainText, const VirgilByteArray& key, const VirgilByteArray& nonce,
                const VirgilByteArray& authData) const override {
            return impl_.encrypt(plainText, key, nonce, authData);
        }

        VirgilByteArray doDecrypt(
                const VirgilByteArray& plainText, const VirgilByteArray& key, const VirgilByteArray& nonce,
                const VirgilByteArray& authData) const override {
            return impl_.decrypt(plainText, key, nonce, authData);
        }

    private:
        Impl impl_;
    };

private:
    std::shared_ptr<const Concept> self_;
};

}}}

#endif //VIRGIL_CRYPTO_VIRGIL_SYMMETRIC_CIPHER_H
