/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#define MODULE_NAME "VirgilAsn1Writer"

#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <cmath>

#include <tinyformat/tinyformat.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>

#include <virgil/crypto/internal/utils.h>
#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

using virgil::crypto::VirgilByteArray;

using virgil::crypto::foundation::asn1::VirgilAsn1Writer;


static const size_t kBufLenDefault = 128;

static const size_t kAsn1TagValueSize = 1;
static const size_t kAsn1LengthValueSize = 3;
static const size_t kAsn1IntegerValueSize = kAsn1TagValueSize + kAsn1LengthValueSize + 8;
static const size_t kAsn1BoolValueSize = 3;
static const size_t kAsn1NullValueSize = kAsn1TagValueSize + 1;
static const size_t kAsn1SizeMax = 65535 + kAsn1TagValueSize + 3; // According to MbedTLS restriction on TAG: LENGTH
static const size_t kAsn1ContextTagMax = 0x1E;

#define RETURN_POINTER_DIFF_AFTER_INVOCATION(pointer, invocation) \
do { \
    unsigned char *before = pointer; \
    do { invocation; } while (0); \
    unsigned char *after = pointer; \
    return (ptrdiff_t)(before - after); \
} while(0);

VirgilAsn1Writer::VirgilAsn1Writer() : p_(0), start_(0), buf_(0), bufLen_(0) {
    this->reset();
}

VirgilAsn1Writer::VirgilAsn1Writer(size_t capacity) : p_(0), start_(0), buf_(0), bufLen_(0) {
    this->reset(capacity);
}

VirgilAsn1Writer::~VirgilAsn1Writer() noexcept {
    dispose();
}

void VirgilAsn1Writer::reset() {
    this->reset(kBufLenDefault);
}

void VirgilAsn1Writer::reset(size_t capacity) {
    if (capacity == 0) {
        throw make_error(VirgilCryptoError::InvalidArgument);
    }
    dispose();
    relocateBuffer(capacity);
}

VirgilByteArray VirgilAsn1Writer::finish() {
    checkState();
    VirgilByteArray result = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_, bufLen_ - (p_ - start_));
    dispose();
    return result;
}

size_t VirgilAsn1Writer::writeInteger(int value) {
    checkState();
    ensureBufferEnough(kAsn1IntegerValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            system_crypto_handler(
                    mbedtls_asn1_write_int(&p_, start_, value)
            )
    );
}

size_t VirgilAsn1Writer::writeBool(bool value) {
    checkState();
    ensureBufferEnough(kAsn1BoolValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            system_crypto_handler(
                    mbedtls_asn1_write_bool(&p_, start_, value)
            )
    );
}

size_t VirgilAsn1Writer::writeNull() {
    checkState();
    ensureBufferEnough(kAsn1NullValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            system_crypto_handler(
                    mbedtls_asn1_write_null(&p_, start_)
            )
    );
}

size_t VirgilAsn1Writer::writeOctetString(const VirgilByteArray& data) {
    checkState();
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize + data.size());
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            system_crypto_handler(
                    mbedtls_asn1_write_octet_string(&p_, start_, data.data(), data.size())
            )
    );
}

size_t VirgilAsn1Writer::writeUTF8String(const VirgilByteArray& data) {
    checkState();
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize + data.size());
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                system_crypto_handler(
                        mbedtls_asn1_write_raw_buffer(&p_, start_, data.data(), data.size())
                );
                system_crypto_handler(
                        mbedtls_asn1_write_len(&p_, start_, data.size())
                );
                system_crypto_handler(
                        mbedtls_asn1_write_tag(&p_, start_, MBEDTLS_ASN1_UTF8_STRING)
                );
            }
    );
}

size_t VirgilAsn1Writer::writeContextTag(unsigned char tag, size_t len) {
    checkState();
    if (tag > kAsn1ContextTagMax) {
        throw make_error(VirgilCryptoError::InvalidArgument,
                tfm::format("ASN.1 context tag is too big %s, maximum is %s.", tag, kAsn1ContextTagMax));
    }
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                system_crypto_handler(
                        mbedtls_asn1_write_len(&p_, start_, len)
                );
                system_crypto_handler(
                        mbedtls_asn1_write_tag(&p_, start_,
                                MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag)
                );
            }
    );
}

size_t VirgilAsn1Writer::writeData(const VirgilByteArray& data) {
    checkState();
    ensureBufferEnough(data.size());
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                system_crypto_handler(
                        mbedtls_asn1_write_raw_buffer(&p_, start_, data.data(), data.size())
                );
            }
    );
}


size_t VirgilAsn1Writer::writeOID(const std::string& oid) {
    checkState();
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize + oid.size());
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                system_crypto_handler(
                        mbedtls_asn1_write_oid(&p_, start_, oid.c_str(), oid.size())
                );
            }
    );
}

size_t VirgilAsn1Writer::writeSequence(size_t len) {
    checkState();
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                system_crypto_handler(
                        mbedtls_asn1_write_len(&p_, start_, len)
                );
                system_crypto_handler(
                        mbedtls_asn1_write_tag(&p_, start_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
                );
            }
    );
}

size_t VirgilAsn1Writer::writeSet(const std::vector<VirgilByteArray>& set) {
    checkState();

    size_t setLength = 0;
    for (std::vector<VirgilByteArray>::const_iterator it = set.begin(); it != set.end(); ++it) {
        setLength += it->size();
    }
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize + setLength);

    std::vector<VirgilByteArray> orderedSet(set);
    makeOrderedSet(orderedSet);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                for (std::vector<VirgilByteArray>::const_reverse_iterator it = orderedSet.rbegin();
                     it != orderedSet.rend(); ++it) {
                    system_crypto_handler(
                            mbedtls_asn1_write_raw_buffer(&p_, start_, it->data(), it->size())
                    );
                }
                system_crypto_handler(
                        mbedtls_asn1_write_len(&p_, start_, setLength)
                );
                system_crypto_handler(
                        mbedtls_asn1_write_tag(&p_, start_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)
                );
            }
    );
}

VirgilByteArray VirgilAsn1Writer::makeComparePadding(const VirgilByteArray& asn1, size_t finalSize) {
    VirgilByteArray result = asn1;
    if (result.size() >= finalSize) {
        return result;
    }
    VirgilByteArray::value_type smallestByte = 0x00;
    if (result.size() > 0) {
        smallestByte = *std::min_element(result.begin(), result.end());
        if (smallestByte != 0x00) {
            --smallestByte;
        }
    }
    result.resize(finalSize, smallestByte);
    return result;
}

bool VirgilAsn1Writer::compare(const VirgilByteArray& first, const VirgilByteArray& second) {
    if (first.size() > second.size()) {
        VirgilByteArray paddedSecond = makeComparePadding(second, first.size());
        return std::lexicographical_compare(first.begin(), first.end(), paddedSecond.begin(), paddedSecond.end());
    } else if (second.size() > first.size()) {
        VirgilByteArray paddedFirst = makeComparePadding(first, second.size());
        return std::lexicographical_compare(paddedFirst.begin(), paddedFirst.end(), second.begin(), second.end());
    } else {
        return std::lexicographical_compare(first.begin(), first.end(), second.begin(), second.end());
    }
}

void VirgilAsn1Writer::makeOrderedSet(std::vector<VirgilByteArray>& set) {
    std::sort(set.begin(), set.end(), VirgilAsn1Writer::compare);
}

void VirgilAsn1Writer::checkState() {
    if (p_ == 0 || start_ == 0) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
}

void VirgilAsn1Writer::relocateBuffer(size_t newBufLen) {
    if (newBufLen < bufLen_) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Required buffer size is less then current.");
    }
    unsigned char* newBuf = new unsigned char[newBufLen];
    size_t writtenBytes = 0;
    if (buf_ && p_ && start_) {
        writtenBytes = bufLen_ - (p_ - start_);
        memcpy(newBuf + newBufLen - writtenBytes, p_, writtenBytes);
        delete[] buf_;
    }
    buf_ = newBuf;
    bufLen_ = newBufLen;
    p_ = buf_ + bufLen_ - writtenBytes;
    start_ = buf_;
}

void VirgilAsn1Writer::ensureBufferEnough(size_t len) {
    checkState();
    size_t unusedSpace = (size_t) (p_ - start_);
    if (len > unusedSpace) {
        const size_t usedSpace = bufLen_ - unusedSpace;
        const size_t requiredLenMin = len + usedSpace;
        if (requiredLenMin > kAsn1SizeMax) {
            throw make_error(VirgilCryptoError::ExceededMaxSize, "ASN.1 structure size limit was exceeded.");
        }
        const size_t requiredLenMax =
                (size_t) 1 << (size_t) (std::ceil(std::log((double) requiredLenMin) / std::log(2.0)));
        const size_t adjustedLen = requiredLenMax > kAsn1SizeMax ? kAsn1SizeMax : requiredLenMax;
        relocateBuffer(adjustedLen);
    }
}

void VirgilAsn1Writer::dispose() noexcept {
    p_ = 0;
    start_ = 0;
    bufLen_ = 0;
    if (buf_) {
        delete[] buf_;
        buf_ = 0;
    }
}

