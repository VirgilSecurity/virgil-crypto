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

#ifndef VIRGIL_CRYPTO_MBEDTLS_EXCEPTION_H
#define VIRGIL_CRYPTO_MBEDTLS_EXCEPTION_H

#include <virgil/crypto/VirgilCryptoException.h>

#define MBEDTLS_ERROR_HANDLER(invocation) MBEDTLS_ERROR_HANDLER_DISPOSE(invocation, {})

#define MBEDTLS_ERROR_HANDLER_DISPOSE(invocation, dispose) \
do { \
    int errCode__ = invocation; \
    if (errCode__ < 0) { \
        do { dispose; } while (0); \
        throw PolarsslException(errCode__); \
    } \
} while (0)

#define MBEDTLS_ERROR_HANDLER_CLEANUP(errCode, invocation) \
do { errCode = invocation; if (errCode < 0) { goto cleanup; } } while (0)

#define MBEDTLS_ERROR_MESSAGE_CLEANUP(messageVariable, message) \
do { messageVariable = message; goto cleanup; } while (0)

#define MBEDTLS_ERROR_MESSAGE_HANDLER(messageVariable) \
do { if (messageVariable) throw VirgilCryptoException(messageVariable); } while (0)


namespace virgil { namespace crypto { namespace foundation {

/**
 * @brief Encapsulates low-level domain error of the PolarSSL framework.
 */
class PolarsslException : public virgil::crypto::VirgilCryptoException {
public:
    /**
     * @name Constructor
     */
    ///@{
    /**
     * @brief Creates PolarsslException class object for a given error code.
     *
     * Human-readable error description can be found in the inherited what() method.
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

}}}

#endif /* VIRGIL_CRYPTO_MBEDTLS_EXCEPTION_H */

