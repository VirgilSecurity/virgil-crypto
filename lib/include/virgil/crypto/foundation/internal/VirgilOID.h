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

/**
 * @file VirgilOID.h
 *
 * Additional OID's definition
 */

#ifndef VIRGIL_CRYPTO_VIRGIL_OID_H
#define VIRGIL_CRYPTO_VIRGIL_OID_H

#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>

#include <string>

/**
 * PKCS#7 OIDs
 */
#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07" ///< pkcs-7 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
#define OID_PKCS7_DATA OID_PKCS7 "\x01" ///< data ::= { pkcs-7 1 }
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x02" ///< signedData ::= { pkcs-7 2 }
#define OID_PKCS7_ENVELOPED_DATA OID_PKCS7 "\x03" ///< envelopedData ::= { pkcs-7 3 }
#define OID_PKCS7_SIGNED_AND_ENVELOPED_DATA OID_PKCS7 "\x04" ///< signedAndEnvelopedData ::= { pkcs-7 4 }
#define OID_PKCS7_DIGESTED_DATA OID_PKCS7 "\x05" ///< digestedData ::= { pkcs-7 5 }
#define OID_PKCS7_ENCRYPTED_DATA OID_PKCS7 "\x06" ///< encryptedData ::= { pkcs-7 6 }
#define OID_PKCS7_DATA_WITH_ATTRIBUTES OID_PKCS7 "\x07" ///< dataWithAttributes ::= { pkcs-7 7 }
#define OID_PKCS7_ENCRYPTED_PRIVATE_KEY_INFO OID_PKCS7 "\x08" ///< encryptedPrivateKeyInfo ::= { pkcs-7 8 }

/**
 * PKCS#9 OIDs
 */
#define OID_PKCS9_AUTHENTICATED_DATA MBEDTLS_OID_PKCS9 "\x0F\x01\x02" ///< ct-authData ::= { pkcs-9 smime(16) ct(1) ct-authData(2) }

/**
 * @brief Translate low-level oid to std::string
 */
#define OID_TO_STD_STRING(oid) std::string(oid, MBEDTLS_OID_SIZE(oid))

/**
 * @brief Compares OIDs
 */
bool inline compareOID(const std::string& first, const std::string& second) {
    return (first.size() == second.size()) && memcmp(first.c_str(), second.c_str(), first.size()) == 0;
}

#endif /* VIRGIL_CRYPTO_VIRGIL_OID_H */
