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

#include <virgil/crypto/foundation/priv/VirgilTagFilter.h>

#include <virgil/crypto/VirgilByteArray.h>

using virgil::crypto::foundation::priv::VirgilTagFilter;

using virgil::crypto::VirgilByteArray;

void VirgilTagFilter::reset(size_t tagLen) {
    tagLen_ = tagLen;
    data_.clear();
    tag_.clear();
}

void VirgilTagFilter::process(const VirgilByteArray& data) {
    tag_.insert(tag_.end(), data.begin(), data.end());

    ptrdiff_t tagSurplusLen = tag_.size() - tagLen_;
    if (tagSurplusLen > 0) {
        VirgilByteArray::iterator tagSurplusBegin = tag_.begin();
        VirgilByteArray::iterator tagSurplusEnd = tagSurplusBegin + tagSurplusLen;
        data_.insert(data_.end(), tagSurplusBegin, tagSurplusEnd);
        tag_.erase(tagSurplusBegin, tagSurplusEnd);
    }
}

bool VirgilTagFilter::hasData() const {
    return !data_.empty();
}

VirgilByteArray VirgilTagFilter::popData() {
    VirgilByteArray result;
    result.swap(data_);
    return result;
}

VirgilByteArray VirgilTagFilter::tag() const {
    return tag_;
}
