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

#ifndef VIRGIL_CRYPTO_CONTENT_INFO_FILTER_H
#define VIRGIL_CRYPTO_CONTENT_INFO_FILTER_H

#include <virgil/crypto/VirgilByteArray.h>

#include <memory>

namespace virgil { namespace crypto { namespace internal {

/**
 * This class filters incoming encrypted data and extracts content info.
 *
 * If content info is a part of encrypted data it must be located at the beginning.
 *
 * To track filtering status inner state machine is used.
 *
 *                                 reset
 *                                   |
 *              interrupt  +---------v---------+
 *            +------------+ waiting preamble  |
 *            | invalid    +---------+---------+
 *            |                      |
 *  +---------v---------+  +---------v---------+
 *  | not found         |  | waiting body      +--interrupt-+
 *  +---------+---------+  +---------+---------+            |
 *            |                      |                      |
 *            |            +---------v---------+  +---------v---------+
 *            |            | found             |  | broken            |
 *            |            +---------+---------+  +-------------------+
 *            |                      |
 *          finish                 finish
 *            |                      |
 *            |            +---------v---------+
 *            +------------> done              |
 *                         +-------------------+
 *
 */
class VirgilContentInfoFilter {
public:

    /**
     * Setup inner state.
     */
    VirgilContentInfoFilter();

    /**
     * Reset inner state to initial.
     * State: waiting preamble.
     */
    void reset();

    /**
     * Change current state to the one of terminal states.
     *
     * From "found" -> "done.
     * From "not found" -> "done.
     *
     * Prerequisite: state must be one of {"found, "not found"}.
     */
    void finish();

    /**
     * Tell filter that passing encrypted data is over.
     *
     * It is also change internal state to "not found" or "broken".
     */
    void tellLastChunk();

    /**
     * Filter given encrypted data to define Content Info.
     * @param encryptedData - data to be filtered.
     */
    void filterData(const VirgilByteArray& encryptedData);

    /**
     * Return true if filter needs more data for analyzing.
     */
    bool isWaitingData() const;

    /**
     * Return true if content info was found in the filtered data.
     *
     * @see popContentInfo() - to extract found content info.
     */
    bool isContentInfoFound() const;

    /**
     * Return true if given data does not begins with content info.
     */
    bool isContentInfoAbsent() const;

    /**
     * Return true if content info beginning was found, but rest of it was not added to the filter.
     *
     * Note, this method can be used after method @link finish() @endlink invocation.
     */
    bool isContentInfoBroken() const;

    /**
     * Returns true if filter has done it's job.
     *
     * Done means that either content info was found and extracted,
     * either content info was not found and client has already handle this.
     *
     * Note, this method can be used after method @link finish() @endlink invocation.
     */
    bool isDone() const;

    /**
     * Returns found content info.
     *
     * Precondition: state must be "found"
     *
     * Note, content info can be extracted once.
     */
    VirgilByteArray popContentInfo();

    /**
     * Returns encrypted data and removes it from the filter.
     *
     * Note, returned data can be empty.
     */
    VirgilByteArray popEncryptedData();

public:
    //! @cond Doxygen_Suppress
    VirgilContentInfoFilter(VirgilContentInfoFilter&& rhs) noexcept;

    VirgilContentInfoFilter& operator=(VirgilContentInfoFilter&& rhs) noexcept;

    ~VirgilContentInfoFilter() noexcept;
    //! @endcond

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace internal
} // namespace crypto
} // namespace virgil

#endif // VIRGIL_CRYPTO_CONTENT_INFO_FILTER_H
