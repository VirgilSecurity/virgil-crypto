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

#ifndef VIRGIL_CRYPTO_VIRGIL_ASN1_WRITER_H
#define VIRGIL_CRYPTO_VIRGIL_ASN1_WRITER_H

#include <cstddef>
#include <string>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

namespace virgil { namespace crypto {

/**
 * @brief This class provides methods for writing ASN.1 data structure.
 *
 * @note All "write*" methods perform writing of ASN.1 structure sequentially.
 * @note Implementation is not complete yet, only minimum set of operations are supported.
 */
class VirgilAsn1Writer {
public:
    /**
     * @brief Initialize internal state for first use.
     * @see @link reset @endlink method for reusing this class to create new ASN.1 stucture.
     */
    VirgilAsn1Writer();
    /**
     * @brief Dispose internal resources.
     */
    ~VirgilAsn1Writer() throw();
    /**
     * @name Start and Finish writing
     */
    ///@{
    /**
     * @brief Reset all internal states and prepare to new ASN.1 writing operations.
     */
    void reset();
    /**
     * @brief Returns the result ASN.1 structure.
     * @return ASN.1 structure that was written.
     * @warning After call this method all attempts to write more data will cause exceptions.
     */
    VirgilByteArray finish();
    ///@}
    /**
     * @name Write Simple ASN.1 Types
     */
    ///@{
    /**
     * @brief Write ASN.1 type: INTEGER.
     * @param value - integer value to be written.
     * @return Written bytes.
     */
    size_t writeInteger(int value);
    /**
     * @brief Write ASN.1 type: NULL.
     * @return Written bytes.
     */
    size_t writeNull();
    /**
     * @brief Write ASN.1 type: OCTET STRING.
     * @param data - octet string to be written.
     * @return Written bytes.
     */
    size_t writeOctetString(const VirgilByteArray& data);
    /**
     * @brief Write ASN.1 type: UTF8String.
     * @param data - UTF8 string to be written.
     * @return Written bytes.
     */
    size_t writeUTF8String(const VirgilByteArray& data);
    /**
     * @brief Write ASN.1 type: TAG.
     * @param tag - custom tag.
     * @param len - length of the taged element, use methods return value to calculate it.
     * @return Written bytes.
     */
    size_t writeContextTag(unsigned char tag, size_t len);
    ///@}
    /**
     * @name Write Structured ASN.1 Types
     */
    ///@{
    /**
     * @brief Write ASN.1 type: SEQUENCE.
     * @param len - sequence length in bytes.
     * @return Written bytes.
     */
    size_t writeSequence(size_t len);
    /**
     * @brief Write an OID tag (ASN1_OID) and data in ASN.1 format.
     * @param oid - the OID to write.
     * @return Written bytes.
     */
    size_t writeOID(const std::string& oid);
     ///@}
private:
    /**
     * @brief Check internal state before methods call.
     * @exception VirgilException - if internal state is not consistent.
     */
    void checkState();
    /**
     * @brief Dispose internal resources.
     */
    void dispose() throw();
    /**
     * @brief Reserve additional space for ASN.1 buffer.
     * @param newBufLen - new ASN.1 buffer size in bytes.
     * @note newBufLen MUST be greate than current ASN.1 buffer length.
     */
    void relocateBuffer(size_t newBufLen);
    /**
     * @brief Ensures that ASN.1 buffer length enough to be able write data of the given length.
     *
     * If ASN.1 buffer left capacity is not enough to be able write data of the given length,
     *     buffer will be relocated with more capacity.
     */
    void ensureBufferEnough(size_t len);
    /**
     * @brief Deny copy constructor
     */
    VirgilAsn1Writer(const VirgilAsn1Writer& other);
    /**
     * @brief Deny assignment operator
     */
    VirgilAsn1Writer& operator=(const VirgilAsn1Writer& rhs);
private:
    unsigned char *p_;
    unsigned char *start_;
    unsigned char *buf_;
    size_t bufLen_;
};

}}

#endif /* VIRGIL_CRYPTO_VIRGIL_ASN1_WRITER_H */
