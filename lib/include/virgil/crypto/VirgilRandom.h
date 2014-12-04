/**
 * Copyright (C) 2014 Virgil Security Inc.
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

#ifndef VIRGIL_CRYPTO_VIRGIL_RANDOM_H
#define VIRGIL_CRYPTO_VIRGIL_RANDOM_H

#include <cstddef>
#include <virgil/VirgilByteArray.h>

namespace virgil { namespace crypto {

/**
 * @name Forward declarations
 */
///@{
class VirgilRandomImpl;
///@}

/**
 * @brief Provides randomization algorithm.
 */
class VirgilRandom {
public:
    /**
     * @name Creation / Destruction methods
     */
    ///@{
    /**
     * @brief Initialize randomization module with personalization data.
     *
     * @param personalInfo (@see section 8.7.1 of NIST Special Publication 800-90A).
     * @return Random bytes.
     */
    explicit VirgilRandom(const VirgilByteArray& personalInfo);
    ///@}

    /**
     * @name Randomization
     */
    ///@{
    /**
     * @brief Produce random byte sequence.
     *
     * @param bytesNum number of bytes to be generated.
     * @return Random byte sequence.
     */
    VirgilByteArray randomize(size_t bytesNum);
    ///@}

private:
    VirgilRandom(const VirgilRandom& other);
    VirgilRandom& operator=(const VirgilRandom& other);
public:
    virtual ~VirgilRandom() throw();
private:
    VirgilRandomImpl * impl_;
};

}}

#endif /* VIRGIL_CRYPTO_VIRGIL_RANDOM_H */
