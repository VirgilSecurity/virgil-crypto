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

#include <virgil/crypto/VirgilAsn1Reader.h>
using virgil::crypto::VirgilAsn1Reader;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/PolarsslException.h>
#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <cstddef>
#include <polarssl/asn1.h>

VirgilAsn1Reader::VirgilAsn1Reader() : p_(0), end_(0), data_() {
}

VirgilAsn1Reader::VirgilAsn1Reader(const VirgilByteArray& data) :p_(0), end_(0), data_() {
    this->reset(data);
}

VirgilAsn1Reader::~VirgilAsn1Reader() throw() {
    p_ = 0;
    end_ = 0;
}

void VirgilAsn1Reader::reset(const VirgilByteArray& data) {
    data_ = data;
    p_ = const_cast<unsigned char *>(data_.data());
    end_ = p_ + data_.size();
}

size_t VirgilAsn1Reader::readSequence() {
    checkState();
    size_t len;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_tag(&p_, end_, &len, ASN1_CONSTRUCTED | ASN1_SEQUENCE)
    );
    return len;
}

int VirgilAsn1Reader::readInteger() {
    checkState();
    int result;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_int(&p_, end_, &result);
    );
    return result;
}

size_t VirgilAsn1Reader::readContextTag(unsigned char tag) {
    if (tag > 0x1F) {
        throw VirgilCryptoException("Tag value is too big, MAX value is 31.");
    }
    checkState();
    size_t len;
    int result = ::asn1_get_tag(&p_, end_, &len, ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | tag);
    if (result == 0) {
        return len;
    } else if (result == POLARSSL_ERR_ASN1_UNEXPECTED_TAG) {
        return 0;
    } else {
        throw PolarsslException(result);
    }
}

VirgilByteArray VirgilAsn1Reader::readOctetString() {
    checkState();
    size_t len;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_tag(&p_, end_, &len, ASN1_OCTET_STRING)
    );
    p_ += len;
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_ - len, len);
}

VirgilByteArray VirgilAsn1Reader::readUTF8String() {
    checkState();
    size_t len;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_tag(&p_, end_, &len, ASN1_UTF8_STRING)
    );
    p_ += len;
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_ - len, len);
}

void VirgilAsn1Reader::checkState() {
    if (p_ == 0 || end_ == 0) {
        throw VirgilException("Reader was not initialized - 'reset' method was not called.");
    }
    if (p_ >= end_) {
        throw VirgilException("ASN.1 structure was totally read, so no data left to be processed.");
    }
}


