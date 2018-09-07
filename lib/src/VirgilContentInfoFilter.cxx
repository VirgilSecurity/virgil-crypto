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

#include "VirgilContentInfoFilter.h"


#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/VirgilContentInfo.h>

#include "utils.h"

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilContentInfo;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::make_error;
using virgil::crypto::internal::VirgilContentInfoFilter;


namespace virgil { namespace crypto { namespace internal {

enum class State {
    WaitingPreamble,
    WaitingBody,
    NotFound,
    Found,
    Broken,
    Done
};

class VirgilContentInfoFilter::Impl {
public:
    State state = State::WaitingPreamble;
    VirgilByteArray encryptedData;
    VirgilByteArray contentInfoData;
    size_t expectedContentInfoSize = 0;
};

constexpr size_t kContentInfoPreambleSize = 16;

}}}


VirgilContentInfoFilter::VirgilContentInfoFilter(VirgilContentInfoFilter&& rhs) noexcept = default;

VirgilContentInfoFilter& VirgilContentInfoFilter::operator=(VirgilContentInfoFilter&& rhs) noexcept = default;

VirgilContentInfoFilter::~VirgilContentInfoFilter() noexcept = default;


VirgilContentInfoFilter::VirgilContentInfoFilter() : impl_(std::make_unique<Impl>()) {
}

void VirgilContentInfoFilter::reset() {
    impl_->state = State::WaitingPreamble;
    impl_->contentInfoData.clear();
    impl_->encryptedData.clear();
}

void VirgilContentInfoFilter::finish() {
    switch (impl_->state) {
        case State::Found:
        case State::NotFound:
            impl_->state = State::Done;
            return;

        default:
            throw make_error(VirgilCryptoError::InvalidState, "VirgilContentInfoFilter::finish()");
    }
}

void VirgilContentInfoFilter::tellLastChunk() {
    switch (impl_->state) {
        case State::WaitingPreamble:
            impl_->state = State::NotFound;
            impl_->encryptedData.swap(impl_->contentInfoData);
            return;

        case State::WaitingBody:
            impl_->state = State::Broken;
            return;

        case State::Found:
        case State::NotFound:
        case State::Broken:
            return;

        default:
            throw make_error(VirgilCryptoError::InvalidState, "VirgilContentInfoFilter::interrupt()");
    }
}

void VirgilContentInfoFilter::filterData(const VirgilByteArray& encryptedData) {
    if (!isWaitingData()) {
        throw make_error(VirgilCryptoError::InvalidState, "VirgilContentInfoFilter::filterData()");
    }

    // Append new data.
    VirgilByteArrayUtils::append(impl_->contentInfoData, encryptedData);

    // Check preamble size.
    if (impl_->contentInfoData.size() < kContentInfoPreambleSize) {
        return;
    }

    // Define content info first time.
    if (impl_->expectedContentInfoSize == 0) {
        impl_->expectedContentInfoSize = VirgilContentInfo::defineSize(impl_->contentInfoData);
    }

    // If content info size still zero, then it is not a content info.
    if (impl_->expectedContentInfoSize == 0) {
        impl_->encryptedData.swap(impl_->contentInfoData);
        impl_->state = State::NotFound;
        return;
    }

    // Check if content info fully extracted.
    if (impl_->contentInfoData.size() >= impl_->expectedContentInfoSize) {
        size_t contentInfoDataSize = impl_->contentInfoData.size();
        size_t encryptedDataSize = impl_->encryptedData.size();

        impl_->encryptedData.insert(impl_->encryptedData.end(),
                impl_->contentInfoData.begin() + impl_->expectedContentInfoSize, impl_->contentInfoData.end());
        impl_->contentInfoData.resize(impl_->expectedContentInfoSize);
        impl_->state = State::Found;

        encryptedDataSize = impl_->encryptedData.size();
        contentInfoDataSize = impl_->contentInfoData.size();
        return;
    }

    impl_->state = State::WaitingBody;
}

bool VirgilContentInfoFilter::isWaitingData() const {
    return impl_->state == State::WaitingPreamble || impl_->state == State::WaitingBody;
}

bool VirgilContentInfoFilter::isContentInfoFound() const {
    return impl_->state == State::Found;
}

bool VirgilContentInfoFilter::isContentInfoAbsent() const {
    return impl_->state == State::NotFound;
}

bool VirgilContentInfoFilter::isContentInfoBroken() const {
    return impl_->state == State::Broken;
}

bool VirgilContentInfoFilter::isDone() const {
    return impl_->state == State::Done;
}

VirgilByteArray VirgilContentInfoFilter::popContentInfo() {
    if (impl_->state != State::Found) {
        throw make_error(VirgilCryptoError::InvalidState, "VirgilContentInfoFilter::popContentInfo()");
    }

    VirgilByteArray result;

    result.swap(impl_->contentInfoData);

    return result;
}

VirgilByteArray VirgilContentInfoFilter::popEncryptedData() {
    VirgilByteArray result;

    result.swap(impl_->encryptedData);

    return result;
}
