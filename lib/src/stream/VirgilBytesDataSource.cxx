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

#include <virgil/crypto/stream/VirgilBytesDataSource.h>
using virgil::crypto::stream::VirgilBytesDataSource;

#include <virgil/crypto/VirgilByteArray.h>
using virgil::crypto::VirgilByteArray;

#include <algorithm>

static const size_t kChunkSizeMin = 10;

VirgilBytesDataSource::VirgilBytesDataSource(const VirgilByteArray& in, size_t chunkSize)
        : in_(in), chunkSize_(std::max(chunkSize, kChunkSizeMin)), leftBytes_(in.size()) {
}

VirgilBytesDataSource::~VirgilBytesDataSource() throw() {
}

bool VirgilBytesDataSource::hasData() {
    return leftBytes_ > 0;
}

void VirgilBytesDataSource::reset() {
    leftBytes_ = in_.size();
}

VirgilByteArray VirgilBytesDataSource::read() {
    size_t actualChunkSize = std::min(chunkSize_, leftBytes_);
    VirgilByteArray::const_iterator start = in_.begin() + in_.size() - leftBytes_;
    VirgilByteArray::const_iterator end = start + actualChunkSize;
    leftBytes_ -= actualChunkSize;
    return VirgilByteArray(start, end);
}
