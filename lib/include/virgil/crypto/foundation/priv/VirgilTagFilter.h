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

#ifndef VIRGIL_CRYPTO_TAG_FILTER_H
#define VIRGIL_CRYPTO_TAG_FILTER_H

#include <cstddef>

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil { namespace crypto { namespace foundation { namespace priv {

/**
 * @brief This class analize incoming data stream to filter Virgil TAG.
 * @note Virgil TAG MUST be at the end of the data stream.
 */
class VirgilTagFilter {
public:
    /**
     * @brief Base initialization.
     * @note Method reset() MUST be called anyway.
     */
    VirgilTagFilter();

    /**
     * @brief Get ready for data filtration.
     * @param tagLen - length of the expected Virgil TAG.
     * @note This method MUST be called before any data will be processed.
     */
    void reset(size_t tagLen);

    /**
     * @brief Filter given data.
     */
    void process(const virgil::crypto::VirgilByteArray& data);

    /**
     * @brief Return if data exist after filtration.
     */
    bool hasData() const;

    /**
     * @brief Return filtrated data.
     */
    virgil::crypto::VirgilByteArray popData();

    /**
     * @brief Return tag that was extracted from processed data.
     * @note MUST be called after method finish().
     * @return Tag or empty byte array.
     */
    virgil::crypto::VirgilByteArray tag() const;

private:
    size_t tagLen_;
    virgil::crypto::VirgilByteArray data_;
    virgil::crypto::VirgilByteArray tag_;
};

}}}}

#endif /* VIRGIL_CRYPTO_TAG_FILTER_H */
