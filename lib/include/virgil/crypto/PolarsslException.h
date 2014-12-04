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

#ifndef VIRGIL_CRYPTO_POLARSSL_EXCEPTION_H
#define VIRGIL_CRYPTO_POLARSSL_EXCEPTION_H

#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#define POLARSSL_ERROR_HANDLER(invocation) POLARSSL_ERROR_HANDLER_DISPOSE(invocation, {})

#define POLARSSL_ERROR_HANDLER_DISPOSE(invocation, dispose) \
do { \
    int errCode = invocation; \
    if (errCode < 0) { \
        do { dispose; } while (0); \
        throw virgil::crypto::PolarsslException(errCode); \
    } \
} while (0)


namespace virgil { namespace crypto {

/**
 * @brief Encapsulates low-level domain error of the PolarSSL framework.
 */
class PolarsslException : public VirgilCryptoException {
public:
    /**
     * @name Constructor
     */
    ///@{
    /**
     * @brief Creates PolarsslException class object for a given error code.
     *
     * Human-readable error description can be found in @link what() @endlink method.
     * @param errCode - error code returned by one of the underlying PolarSSL framework functions.
     */
    explicit PolarsslException(int errCode);
    ///@}
    /**
     * @name Destructor
     */
    ///@{
    virtual ~PolarsslException() throw();
    ///@}
    /**
     * @name Info
     */
    ///@{
    /**
     * @brief Provide low-level PolarSSL fremowork error code.
     * @return Low-level PolarSSL fremowork error code.
     */
    int errCode() const throw();
    ///@}
private:
    int errCode_;
};

}}

#endif /* VIRGIL_CRYPTO_POLARSSL_EXCEPTION_H */

