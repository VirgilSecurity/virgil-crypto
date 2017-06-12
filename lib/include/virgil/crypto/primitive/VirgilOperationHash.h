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

#ifndef VIRGIL_CRYPTO_VIRGIL_HASH_H
#define VIRGIL_CRYPTO_VIRGIL_HASH_H

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil { namespace crypto { inline namespace primitive {

class VirgilOperationHash {
private:
    template<class Impl>
    struct Model;;

public:
    template<class Impl>
    VirgilOperationHash(Impl impl) : self_(new Model<Impl>(std::move(impl))) {}

    VirgilOperationHash(const VirgilOperationHash& other) : self_(other.self_->doCopy()) {}

    VirgilOperationHash(VirgilOperationHash&& other)noexcept = default;

    VirgilOperationHash& operator=(const VirgilOperationHash& other) {
        VirgilOperationHash tmp(other);
        *this = std::move(tmp);
        return *this;
    }

    VirgilOperationHash& operator=(VirgilOperationHash&& other)noexcept= default;

    ~VirgilOperationHash()noexcept = default;;

    VirgilByteArray hash(const VirgilByteArray& data) {
        self_->doStart();
        self_->doUpdate(data);
        return self_->doFinish();
    }

    void start() {
        self_->doStart();
    }

    void update(const VirgilByteArray& data) {
        self_->doUpdate(data);
    }

    VirgilByteArray finish() {
        return self_->doFinish();
    }

    static VirgilOperationHash getDefault();

private:
    struct Concept {
        virtual Concept* doCopy() const = 0;

        virtual void doStart() = 0;

        virtual void doUpdate(const VirgilByteArray& data) = 0;

        virtual VirgilByteArray doFinish() = 0;
    };

    template<class Impl>
    struct Model : Concept {

        explicit Model(Impl impl) : impl_(std::move(impl)) {}

        Concept* doCopy() const override {
            return new Model(*this);
        }

        void doStart() override {
            return impl_.start();
        }

        void doUpdate(const VirgilByteArray& data) override {
            impl_.update(data);
        }

        VirgilByteArray doFinish() override {
            return impl_.finish();
        }

    private:
        Impl impl_;
    };

private:
    std::unique_ptr<Concept> self_;
};

}}}

#endif //VIRGIL_CRYPTO_VIRGIL_HASH_H
