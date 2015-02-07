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

#ifndef VIRGIL_CRYPTO_ASN1_VIRGIL_ASN1_COMPATIBLE_H
#define VIRGIL_CRYPTO_ASN1_VIRGIL_ASN1_COMPATIBLE_H

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace virgil { namespace crypto { namespace asn1 {

/**
 * @brief This class provides interface that allow to save and restore object state in the ASN.1 structure.
 */
class VirgilAsn1Compatible {
public:
    /**
     * @brief Save object state to the ASN.1 structure.
     */
    virtual VirgilByteArray toAsn1() const = 0;
    /**
     * @brief Restore object state from the ASN.1 structure.
     */
    virtual void fromAsn1(const VirgilByteArray& asn1) = 0;
    /**
     * @brief Polymorphic destructor.
     */
     virtual ~VirgilAsn1Compatible() throw() {}
protected:
    /**
     * @brief If given parameter is empty exception will be thrown.
     * @throw virgil::crypto::VirgilCryptoException.
     */
    virtual void checkAsn1ParamNotEmpty(const VirgilByteArray& param, const char *paramName = 0) const;
};

}}}

#endif /* VIRGIL_CRYPTO_ASN1_VIRGIL_ASN1_COMPATIBLE_H */
